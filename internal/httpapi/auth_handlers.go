package httpapi

import (
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"strings"
	"time"

	"example.com/go-security-api/internal/audit"
	"example.com/go-security-api/internal/auth"
)

const sessionCookieName = "sid"

func registerAuthRoutes(mux *http.ServeMux, service *auth.Service, auditor *audit.Service, cookieSecure bool) {
	mux.HandleFunc("POST /api/v1/auth/register", registerHandler(service, auditor))
	mux.HandleFunc("POST /api/v1/auth/login", loginHandler(service, auditor, cookieSecure))
	mux.HandleFunc("POST /api/v1/auth/logout", logoutHandler(service, auditor, cookieSecure))
	mux.Handle("GET /api/v1/auth/me", requireSession(service, auditor, http.HandlerFunc(meHandler(auditor))))
}

func registerHandler(service *auth.Service, auditor *audit.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if service == nil {
			recordAudit(auditor, r, "auth.register", "failure", http.StatusServiceUnavailable, "user", nil, map[string]any{"reason": "service_unavailable"})
			writeError(w, http.StatusServiceUnavailable, "auth_unavailable", "authentication is not configured", r)
			return
		}

		var input credentialsRequest
		if err := decodeJSON(w, r, &input); err != nil {
			recordAudit(auditor, r, "auth.register", "failure", http.StatusBadRequest, "user", nil, map[string]any{"reason": "invalid_json"})
			writeError(w, http.StatusBadRequest, "invalid_json", "request body is invalid", r)
			return
		}

		user, err := service.Register(r.Context(), input.Email, input.Password)
		if err != nil {
			switch {
			case errors.Is(err, auth.ErrEmailExists):
				recordAudit(auditor, r, "auth.register", "denied", http.StatusConflict, "user", nil, map[string]any{"reason": "email_exists"})
				writeError(w, http.StatusConflict, "email_exists", "email is already registered", r)
			case errors.Is(err, auth.ErrInvalidInput):
				recordAudit(auditor, r, "auth.register", "denied", http.StatusBadRequest, "user", nil, map[string]any{"reason": "invalid_input"})
				writeError(w, http.StatusBadRequest, "invalid_input", "email or password is invalid", r)
			default:
				recordAudit(auditor, r, "auth.register", "failure", http.StatusInternalServerError, "user", nil, map[string]any{"reason": "registration_failed"})
				writeError(w, http.StatusInternalServerError, "registration_failed", "registration failed", r)
			}
			return
		}

		recordAuditForUser(auditor, r, user, "auth.register", "success", http.StatusCreated, "user", &user.ID, nil)
		writeJSON(w, http.StatusCreated, userResponse(user))
	}
}

func loginHandler(service *auth.Service, auditor *audit.Service, cookieSecure bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if service == nil {
			recordAudit(auditor, r, "auth.login", "failure", http.StatusServiceUnavailable, "user", nil, map[string]any{"reason": "service_unavailable"})
			writeError(w, http.StatusServiceUnavailable, "auth_unavailable", "authentication is not configured", r)
			return
		}

		var input credentialsRequest
		if err := decodeJSON(w, r, &input); err != nil {
			recordAudit(auditor, r, "auth.login", "failure", http.StatusBadRequest, "user", nil, map[string]any{"reason": "invalid_json"})
			writeError(w, http.StatusBadRequest, "invalid_json", "request body is invalid", r)
			return
		}

		user, token, expiresAt, err := service.Login(r.Context(), input.Email, input.Password, r.UserAgent(), clientIP(r))
		if err != nil {
			if errors.Is(err, auth.ErrInvalidCredentials) || errors.Is(err, auth.ErrUserBlocked) {
				recordAudit(auditor, r, "auth.login", "denied", http.StatusUnauthorized, "user", nil, map[string]any{"reason": "invalid_credentials"})
				writeError(w, http.StatusUnauthorized, "invalid_credentials", "email or password is invalid", r)
				return
			}
			recordAudit(auditor, r, "auth.login", "failure", http.StatusInternalServerError, "user", nil, map[string]any{"reason": "login_failed"})
			writeError(w, http.StatusInternalServerError, "login_failed", "login failed", r)
			return
		}

		http.SetCookie(w, &http.Cookie{
			Name:     sessionCookieName,
			Value:    token,
			Path:     "/",
			Expires:  expiresAt,
			MaxAge:   maxAge(expiresAt),
			HttpOnly: true,
			Secure:   cookieSecure,
			SameSite: http.SameSiteLaxMode,
		})
		recordAuditForUser(auditor, r, user, "auth.login", "success", http.StatusOK, "user", &user.ID, map[string]any{"session_ttl_seconds": int(time.Until(expiresAt).Seconds())})
		writeJSON(w, http.StatusOK, userResponse(user))
	}
}

func logoutHandler(service *auth.Service, auditor *audit.Service, cookieSecure bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if service != nil {
			if cookie, err := r.Cookie(sessionCookieName); err == nil {
				_ = service.Logout(r.Context(), cookie.Value)
			}
		}
		http.SetCookie(w, &http.Cookie{
			Name:     sessionCookieName,
			Value:    "",
			Path:     "/",
			MaxAge:   -1,
			Expires:  time.Unix(1, 0),
			HttpOnly: true,
			Secure:   cookieSecure,
			SameSite: http.SameSiteLaxMode,
		})
		recordAudit(auditor, r, "auth.logout", "success", http.StatusNoContent, "session", nil, nil)
		w.WriteHeader(http.StatusNoContent)
	}
}

func requireSession(service *auth.Service, auditor *audit.Service, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if service == nil {
			recordAudit(auditor, r, "auth.session", "failure", http.StatusServiceUnavailable, "session", nil, map[string]any{"reason": "service_unavailable"})
			writeError(w, http.StatusServiceUnavailable, "auth_unavailable", "authentication is not configured", r)
			return
		}
		cookie, err := r.Cookie(sessionCookieName)
		if err != nil || strings.TrimSpace(cookie.Value) == "" {
			recordAudit(auditor, r, "auth.session", "denied", http.StatusUnauthorized, "session", nil, map[string]any{"reason": "missing_session"})
			writeError(w, http.StatusUnauthorized, "unauthenticated", "authentication is required", r)
			return
		}

		user, _, err := service.Authenticate(r.Context(), cookie.Value)
		if err != nil {
			recordAudit(auditor, r, "auth.session", "denied", http.StatusUnauthorized, "session", nil, map[string]any{"reason": "invalid_session"})
			writeError(w, http.StatusUnauthorized, "unauthenticated", "authentication is required", r)
			return
		}
		next.ServeHTTP(w, r.WithContext(auth.WithUser(r.Context(), user)))
	})
}

func meHandler(auditor *audit.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user, ok := auth.UserFromContext(r.Context())
		if !ok {
			writeError(w, http.StatusUnauthorized, "unauthenticated", "authentication is required", r)
			return
		}
		recordAuditForUser(auditor, r, user, "auth.me", "success", http.StatusOK, "user", &user.ID, nil)
		writeJSON(w, http.StatusOK, userResponse(user))
	}
}

type credentialsRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

func userResponse(user auth.User) map[string]any {
	return map[string]any{
		"id":         user.ID.String(),
		"email":      user.Email,
		"role":       user.Role,
		"status":     user.Status,
		"created_at": user.CreatedAt,
	}
}

func decodeJSON(w http.ResponseWriter, r *http.Request, destination any) error {
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20))
	decoder.DisallowUnknownFields()
	return decoder.Decode(destination)
}

func writeError(w http.ResponseWriter, status int, code, message string, r *http.Request) {
	writeJSON(w, status, map[string]any{
		"error":      code,
		"message":    message,
		"request_id": requestIDFromContextValue(r.Context()),
	})
}

func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil {
		return host
	}
	return r.RemoteAddr
}

func maxAge(expiresAt time.Time) int {
	seconds := int(time.Until(expiresAt).Seconds())
	if seconds < 1 {
		return 1
	}
	return seconds
}
