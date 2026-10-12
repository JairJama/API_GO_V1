package httpapi

import (
	"errors"
	"net/http"

	"example.com/go-security-api/internal/audit"
	"example.com/go-security-api/internal/passwordreset"
)

type forgotPasswordRequest struct {
	Email string `json:"email"`
}

type resetPasswordRequest struct {
	Token    string `json:"token"`
	Password string `json:"password"`
}

func forgotPasswordHandler(service *passwordreset.Service, auditor *audit.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if service == nil {
			recordAudit(auditor, r, "auth.password_reset.requested", "failure", http.StatusServiceUnavailable, "user", nil, map[string]any{"reason": "service_unavailable"})
			writeError(w, http.StatusServiceUnavailable, "password_reset_unavailable", "password reset is not configured", r)
			return
		}

		var input forgotPasswordRequest
		if err := decodeJSON(w, r, &input); err != nil {
			recordAudit(auditor, r, "auth.password_reset.denied", "denied", http.StatusBadRequest, "user", nil, map[string]any{"reason": "invalid_json"})
			writeError(w, http.StatusBadRequest, "invalid_json", "request body is invalid", r)
			return
		}

		result, err := service.Request(r.Context(), input.Email, clientIP(r))
		if errors.Is(err, passwordreset.ErrMailerUnavailable) {
			recordAudit(auditor, r, "auth.password_reset.requested", "failure", http.StatusServiceUnavailable, "user", nil, map[string]any{"reason": "mailer_unavailable"})
			writeError(w, http.StatusServiceUnavailable, "password_reset_unavailable", "password reset is temporarily unavailable", r)
			return
		}
		if err != nil {
			recordAudit(auditor, r, "auth.password_reset.requested", "failure", http.StatusInternalServerError, "user", nil, map[string]any{"reason": "request_failed"})
			writeError(w, http.StatusInternalServerError, "password_reset_failed", "password reset request failed", r)
			return
		}
		if result.RateLimited {
			recordAudit(auditor, r, "auth.password_reset.denied", "denied", http.StatusAccepted, "user", nil, map[string]any{"reason": "rate_limited"})
		} else {
			recordAudit(auditor, r, "auth.password_reset.requested", "success", http.StatusAccepted, "user", result.UserID, nil)
		}
		w.WriteHeader(http.StatusAccepted)
	}
}

func resetPasswordHandler(service *passwordreset.Service, auditor *audit.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if service == nil {
			recordAudit(auditor, r, "auth.password_reset.denied", "failure", http.StatusServiceUnavailable, "user", nil, map[string]any{"reason": "service_unavailable"})
			writeError(w, http.StatusServiceUnavailable, "password_reset_unavailable", "password reset is not configured", r)
			return
		}

		var input resetPasswordRequest
		if err := decodeJSON(w, r, &input); err != nil {
			recordAudit(auditor, r, "auth.password_reset.denied", "denied", http.StatusBadRequest, "user", nil, map[string]any{"reason": "invalid_json"})
			writeError(w, http.StatusBadRequest, "invalid_json", "request body is invalid", r)
			return
		}
		user, err := service.Reset(r.Context(), input.Token, input.Password)
		if errors.Is(err, passwordreset.ErrInvalidToken) {
			recordAudit(auditor, r, "auth.password_reset.denied", "denied", http.StatusBadRequest, "user", nil, map[string]any{"reason": "invalid_or_expired_token"})
			writeError(w, http.StatusBadRequest, "invalid_reset", "token or password is invalid", r)
			return
		}
		if err != nil {
			recordAudit(auditor, r, "auth.password_reset.denied", "failure", http.StatusInternalServerError, "user", nil, map[string]any{"reason": "reset_failed"})
			writeError(w, http.StatusInternalServerError, "password_reset_failed", "password reset failed", r)
			return
		}
		recordAuditForUser(auditor, r, user, "auth.password_reset.completed", "success", http.StatusNoContent, "user", &user.ID, nil)
		w.WriteHeader(http.StatusNoContent)
	}
}
