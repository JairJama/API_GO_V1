package httpapi

import (
	"net/http"
	"strings"

	"example.com/go-security-api/internal/audit"
	"example.com/go-security-api/internal/auth"
	"github.com/google/uuid"
)

func recordAudit(auditor *audit.Service, r *http.Request, action, outcome string, status int, resourceType string, resourceID *uuid.UUID, metadata map[string]any) {
	if auditor == nil {
		return
	}

	actorType := "anonymous"
	var actorID *uuid.UUID
	if user, ok := auth.UserFromContext(r.Context()); ok {
		actorType = "human"
		id := user.ID
		actorID = &id
	}

	_ = auditor.Record(r.Context(), audit.Entry{
		RequestID:    requestIDFromContextValue(r.Context()),
		ActorType:    actorType,
		ActorID:      actorID,
		Action:       action,
		Outcome:      outcome,
		HTTPMethod:   r.Method,
		Route:        requestRoute(r),
		StatusCode:   status,
		ResourceType: resourceType,
		ResourceID:   resourceID,
		Metadata:     safeAuditMetadata(metadata),
	})
}

func recordAuditForUser(auditor *audit.Service, r *http.Request, user auth.User, action, outcome string, status int, resourceType string, resourceID *uuid.UUID, metadata map[string]any) {
	if auditor == nil {
		return
	}
	id := user.ID
	_ = auditor.Record(r.Context(), audit.Entry{
		RequestID:    requestIDFromContextValue(r.Context()),
		ActorType:    "human",
		ActorID:      &id,
		Action:       action,
		Outcome:      outcome,
		HTTPMethod:   r.Method,
		Route:        requestRoute(r),
		StatusCode:   status,
		ResourceType: resourceType,
		ResourceID:   resourceID,
		Metadata:     safeAuditMetadata(metadata),
	})
}

func requestRoute(r *http.Request) string {
	if r.Pattern != "" {
		return r.Pattern
	}
	return r.URL.Path
}

func safeAuditMetadata(metadata map[string]any) map[string]any {
	if len(metadata) == 0 {
		return map[string]any{}
	}
	result := make(map[string]any, len(metadata))
	for key, value := range metadata {
		if isSensitiveAuditKey(key) {
			continue
		}
		result[key] = value
	}
	return result
}

func isSensitiveAuditKey(key string) bool {
	key = strings.ToLower(strings.ReplaceAll(key, "-", "_"))
	switch key {
	case "password", "password_hash", "token", "access_token", "refresh_token", "cookie", "secret", "authorization", "recovery_code":
		return true
	default:
		return strings.Contains(key, "password") || strings.Contains(key, "token") || strings.Contains(key, "secret")
	}
}

func outcomeForStatus(status int) string {
	if status >= http.StatusOK && status < http.StatusMultipleChoices {
		return "success"
	}
	if status == http.StatusUnauthorized || status == http.StatusForbidden || status == http.StatusNotFound {
		return "denied"
	}
	return "failure"
}
