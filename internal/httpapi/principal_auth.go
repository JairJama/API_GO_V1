package httpapi

import (
	"errors"
	"net/http"
	"strings"

	"example.com/go-security-api/internal/audit"
	"example.com/go-security-api/internal/auth"
	"example.com/go-security-api/internal/principal"
	"example.com/go-security-api/internal/serviceaccounts"
)

// AuthenticatePrincipal gives Bearer credentials precedence over a session cookie.
func AuthenticatePrincipal(authentication *auth.Service, tokens *serviceaccounts.Service, auditor *audit.Service, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authorization := strings.TrimSpace(r.Header.Get("Authorization"))
		if authorization != "" {
			parts := strings.Fields(authorization)
			if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") || tokens == nil {
				recordAudit(auditor, r, "auth.bearer.denied", "denied", http.StatusUnauthorized, "api_token", nil, map[string]any{"reason": "invalid_bearer"})
				writeError(w, http.StatusUnauthorized, "unauthenticated", "authentication is required", r)
				return
			}
			actor, err := tokens.Authenticate(r.Context(), parts[1], clientIP(r))
			if err != nil {
				outcome := "denied"
				if !errors.Is(err, serviceaccounts.ErrUnauthenticated) {
					outcome = "failure"
				}
				recordAudit(auditor, r, "auth.bearer.denied", outcome, http.StatusUnauthorized, "api_token", nil, map[string]any{"reason": "invalid_bearer"})
				writeError(w, http.StatusUnauthorized, "unauthenticated", "authentication is required", r)
				return
			}
			ctx := principal.With(r.Context(), actor)
			recordAudit(auditor, r.WithContext(ctx), "auth.bearer.success", "success", http.StatusOK, "service_account", &actor.ID, nil)
			next.ServeHTTP(w, r.WithContext(ctx))
			return
		}

		if authentication == nil {
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
		user, _, err := authentication.Authenticate(r.Context(), cookie.Value)
		if err != nil {
			recordAudit(auditor, r, "auth.session", "denied", http.StatusUnauthorized, "session", nil, map[string]any{"reason": "invalid_session"})
			writeError(w, http.StatusUnauthorized, "unauthenticated", "authentication is required", r)
			return
		}
		actor := principal.Principal{Type: principal.Human, ID: user.ID}
		ctx := principal.With(auth.WithUser(r.Context(), user), actor)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func requireHumanPrincipal(auditor *audit.Service, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		actor, ok := principal.FromContext(r.Context())
		if !ok || actor.Type != principal.Human {
			recordAudit(auditor, r, "authorization.denied", "denied", http.StatusForbidden, "principal", nil, map[string]any{"reason": "human_principal_required"})
			writeError(w, http.StatusForbidden, "forbidden", "a human user is required for this operation", r)
			return
		}
		next.ServeHTTP(w, r)
	})
}
