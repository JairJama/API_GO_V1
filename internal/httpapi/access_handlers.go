package httpapi

import (
	"context"
	"net/http"
	"sort"

	"example.com/go-security-api/internal/access"
	"example.com/go-security-api/internal/audit"
	"example.com/go-security-api/internal/auth"
)

func registerAccessRoutes(mux *http.ServeMux, authentication *auth.Service, authorization *access.Service, auditor *audit.Service) {
	mux.Handle("GET /api/v1/admin/access", requireSession(authentication, auditor,
		requirePermission(authorization, auditor, "users.read", http.HandlerFunc(accessHandler))))
}

func requirePermission(service *access.Service, auditor *audit.Service, permission string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if service == nil {
			recordAudit(auditor, r, "authorization.check", "failure", http.StatusServiceUnavailable, "permission", nil, map[string]any{"permission": permission, "reason": "service_unavailable"})
			writeError(w, http.StatusServiceUnavailable, "authorization_unavailable", "authorization is not configured", r)
			return
		}

		user, ok := auth.UserFromContext(r.Context())
		if !ok {
			recordAudit(auditor, r, "authorization.check", "denied", http.StatusUnauthorized, "permission", nil, map[string]any{"permission": permission, "reason": "missing_user"})
			writeError(w, http.StatusUnauthorized, "unauthenticated", "authentication is required", r)
			return
		}

		allowed, err := service.Has(r.Context(), user.ID, permission)
		if err != nil {
			recordAuditForUser(auditor, r, user, "authorization.check", "failure", http.StatusInternalServerError, "permission", nil, map[string]any{"permission": permission, "reason": "permission_lookup_failed"})
			writeError(w, http.StatusInternalServerError, "authorization_failed", "authorization could not be evaluated", r)
			return
		}
		if !allowed {
			recordAuditForUser(auditor, r, user, "authorization.denied", "denied", http.StatusForbidden, "permission", nil, map[string]any{"permission": permission})
			writeError(w, http.StatusForbidden, "forbidden", "the required permission is not assigned", r)
			return
		}

		recordAuditForUser(auditor, r, user, "authorization.allowed", "success", http.StatusOK, "permission", nil, map[string]any{"permission": permission})
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), accessServiceKey{}, service)))
	})
}

func accessHandler(w http.ResponseWriter, r *http.Request) {
	user, ok := auth.UserFromContext(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthenticated", "authentication is required", r)
		return
	}

	// The middleware already checked users.read. Loading the set again makes
	// this endpoint useful as a small observable RBAC demonstration.
	service, ok := r.Context().Value(accessServiceKey{}).(*access.Service)
	if !ok || service == nil {
		writeError(w, http.StatusInternalServerError, "authorization_failed", "authorization is not available", r)
		return
	}
	permissions, err := service.Permissions(r.Context(), user.ID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "authorization_failed", "authorization could not be loaded", r)
		return
	}

	list := make([]string, 0, len(permissions))
	for permission := range permissions {
		list = append(list, permission)
	}
	sort.Strings(list)
	writeJSON(w, http.StatusOK, map[string]any{
		"authorized":  true,
		"permission":  "users.read",
		"user_id":     user.ID.String(),
		"permissions": list,
	})
}

type accessServiceKey struct{}
