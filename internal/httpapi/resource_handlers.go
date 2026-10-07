package httpapi

import (
	"errors"
	"net/http"
	"strings"

	"example.com/go-security-api/internal/audit"
	"example.com/go-security-api/internal/auth"
	"example.com/go-security-api/internal/resources"
	"github.com/google/uuid"
)

func registerResourceRoutes(mux *http.ServeMux, authentication *auth.Service, resourceService *resources.Service, auditor *audit.Service) {
	mux.Handle("POST /api/v1/organizations", requireSession(authentication, auditor, http.HandlerFunc(createOrganizationHandler(resourceService, auditor))))
	mux.Handle("POST /api/v1/organizations/{organization_id}/documents", requireSession(authentication, auditor, http.HandlerFunc(createDocumentHandler(resourceService, auditor))))
	mux.Handle("GET /api/v1/organizations/{organization_id}/documents/{document_id}", requireSession(authentication, auditor, http.HandlerFunc(getDocumentHandler(resourceService, auditor))))
	mux.Handle("PATCH /api/v1/organizations/{organization_id}/documents/{document_id}", requireSession(authentication, auditor, http.HandlerFunc(updateDocumentHandler(resourceService, auditor))))
	mux.Handle("DELETE /api/v1/organizations/{organization_id}/documents/{document_id}", requireSession(authentication, auditor, http.HandlerFunc(deleteDocumentHandler(resourceService, auditor))))
}

func createOrganizationHandler(service *resources.Service, auditor *audit.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if service == nil {
			recordAudit(auditor, r, "organization.create", "failure", http.StatusServiceUnavailable, "organization", nil, map[string]any{"reason": "service_unavailable"})
			writeError(w, http.StatusServiceUnavailable, "resource_unavailable", "resource service is not configured", r)
			return
		}
		user, ok := auth.UserFromContext(r.Context())
		if !ok {
			writeError(w, http.StatusUnauthorized, "unauthenticated", "authentication is required", r)
			return
		}

		var input organizationRequest
		if err := decodeJSON(w, r, &input); err != nil {
			recordAuditForUser(auditor, r, user, "organization.create", "failure", http.StatusBadRequest, "organization", nil, map[string]any{"reason": "invalid_json"})
			writeError(w, http.StatusBadRequest, "invalid_json", "request body is invalid", r)
			return
		}
		organization, err := service.CreateOrganization(r.Context(), user.ID, input.Name, input.Slug)
		if err != nil {
			recordAuditForUser(auditor, r, user, "organization.create", outcomeForStatus(resourceErrorStatus(err)), resourceErrorStatus(err), "organization", nil, map[string]any{"reason": "operation_failed"})
			writeResourceError(w, r, err)
			return
		}
		recordAuditForUser(auditor, r, user, "organization.create", "success", http.StatusCreated, "organization", &organization.ID, nil)
		writeJSON(w, http.StatusCreated, organization)
	}
}

func createDocumentHandler(service *resources.Service, auditor *audit.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if service == nil {
			recordAudit(auditor, r, "document.create", "failure", http.StatusServiceUnavailable, "document", nil, map[string]any{"reason": "service_unavailable"})
			writeError(w, http.StatusServiceUnavailable, "resource_unavailable", "resource service is not configured", r)
			return
		}
		user, ok := auth.UserFromContext(r.Context())
		if !ok {
			writeError(w, http.StatusUnauthorized, "unauthenticated", "authentication is required", r)
			return
		}
		organizationID, err := pathUUID(r, "organization_id")
		if err != nil {
			recordAuditForUser(auditor, r, user, "document.create", "failure", http.StatusBadRequest, "document", nil, map[string]any{"reason": "invalid_organization_id"})
			writeError(w, http.StatusBadRequest, "invalid_organization_id", "organization id is invalid", r)
			return
		}

		var input documentRequest
		if err := decodeJSON(w, r, &input); err != nil {
			recordAuditForUser(auditor, r, user, "document.create", "failure", http.StatusBadRequest, "document", nil, map[string]any{"reason": "invalid_json"})
			writeError(w, http.StatusBadRequest, "invalid_json", "request body is invalid", r)
			return
		}
		document, err := service.CreateDocument(r.Context(), user.ID, organizationID, input.Title, input.Content)
		if err != nil {
			recordAuditForUser(auditor, r, user, "document.create", outcomeForStatus(resourceErrorStatus(err)), resourceErrorStatus(err), "document", nil, map[string]any{"organization_id": organizationID.String()})
			writeResourceError(w, r, err)
			return
		}
		recordAuditForUser(auditor, r, user, "document.create", "success", http.StatusCreated, "document", &document.ID, map[string]any{"organization_id": organizationID.String()})
		writeJSON(w, http.StatusCreated, document)
	}
}

func getDocumentHandler(service *resources.Service, auditor *audit.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user, ok := auth.UserFromContext(r.Context())
		if !ok {
			writeError(w, http.StatusUnauthorized, "unauthenticated", "authentication is required", r)
			return
		}
		if service == nil {
			recordAuditForUser(auditor, r, user, "document.read", "failure", http.StatusServiceUnavailable, "document", nil, map[string]any{"reason": "service_unavailable"})
			writeError(w, http.StatusServiceUnavailable, "resource_unavailable", "resource service is not configured", r)
			return
		}
		organizationID, documentID, err := documentPathIDs(r)
		if err != nil {
			recordAuditForUser(auditor, r, user, "document.read", "failure", http.StatusBadRequest, "document", nil, map[string]any{"reason": "invalid_resource_id"})
			writeError(w, http.StatusBadRequest, "invalid_resource_id", "organization or document id is invalid", r)
			return
		}
		document, err := service.FindDocument(r.Context(), user.ID, organizationID, documentID)
		if err != nil {
			recordAuditForUser(auditor, r, user, "document.read", outcomeForStatus(resourceErrorStatus(err)), resourceErrorStatus(err), "document", &documentID, map[string]any{"organization_id": organizationID.String()})
			writeResourceError(w, r, err)
			return
		}
		recordAuditForUser(auditor, r, user, "document.read", "success", http.StatusOK, "document", &document.ID, map[string]any{"organization_id": organizationID.String()})
		writeJSON(w, http.StatusOK, document)
	}
}

func updateDocumentHandler(service *resources.Service, auditor *audit.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user, ok := auth.UserFromContext(r.Context())
		if !ok {
			writeError(w, http.StatusUnauthorized, "unauthenticated", "authentication is required", r)
			return
		}
		if service == nil {
			recordAuditForUser(auditor, r, user, "document.update", "failure", http.StatusServiceUnavailable, "document", nil, map[string]any{"reason": "service_unavailable"})
			writeError(w, http.StatusServiceUnavailable, "resource_unavailable", "resource service is not configured", r)
			return
		}
		organizationID, documentID, err := documentPathIDs(r)
		if err != nil {
			recordAuditForUser(auditor, r, user, "document.update", "failure", http.StatusBadRequest, "document", nil, map[string]any{"reason": "invalid_resource_id"})
			writeError(w, http.StatusBadRequest, "invalid_resource_id", "organization or document id is invalid", r)
			return
		}

		var input documentPatchRequest
		if err := decodeJSON(w, r, &input); err != nil {
			recordAuditForUser(auditor, r, user, "document.update", "failure", http.StatusBadRequest, "document", &documentID, map[string]any{"reason": "invalid_json"})
			writeError(w, http.StatusBadRequest, "invalid_json", "request body is invalid", r)
			return
		}
		document, err := service.UpdateDocument(r.Context(), user.ID, organizationID, documentID, input.Title, input.Content)
		if err != nil {
			recordAuditForUser(auditor, r, user, "document.update", outcomeForStatus(resourceErrorStatus(err)), resourceErrorStatus(err), "document", &documentID, map[string]any{"organization_id": organizationID.String()})
			writeResourceError(w, r, err)
			return
		}
		recordAuditForUser(auditor, r, user, "document.update", "success", http.StatusOK, "document", &document.ID, map[string]any{"organization_id": organizationID.String()})
		writeJSON(w, http.StatusOK, document)
	}
}

func deleteDocumentHandler(service *resources.Service, auditor *audit.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user, ok := auth.UserFromContext(r.Context())
		if !ok {
			writeError(w, http.StatusUnauthorized, "unauthenticated", "authentication is required", r)
			return
		}
		if service == nil {
			recordAuditForUser(auditor, r, user, "document.delete", "failure", http.StatusServiceUnavailable, "document", nil, map[string]any{"reason": "service_unavailable"})
			writeError(w, http.StatusServiceUnavailable, "resource_unavailable", "resource service is not configured", r)
			return
		}
		organizationID, documentID, err := documentPathIDs(r)
		if err != nil {
			recordAuditForUser(auditor, r, user, "document.delete", "failure", http.StatusBadRequest, "document", nil, map[string]any{"reason": "invalid_resource_id"})
			writeError(w, http.StatusBadRequest, "invalid_resource_id", "organization or document id is invalid", r)
			return
		}
		if _, err := service.DeleteDocument(r.Context(), user.ID, organizationID, documentID); err != nil {
			recordAuditForUser(auditor, r, user, "document.delete", outcomeForStatus(resourceErrorStatus(err)), resourceErrorStatus(err), "document", &documentID, map[string]any{"organization_id": organizationID.String()})
			writeResourceError(w, r, err)
			return
		}
		recordAuditForUser(auditor, r, user, "document.delete", "success", http.StatusNoContent, "document", &documentID, map[string]any{"organization_id": organizationID.String()})
		w.WriteHeader(http.StatusNoContent)
	}
}

type organizationRequest struct {
	Name string `json:"name"`
	Slug string `json:"slug"`
}

type documentRequest struct {
	Title   string `json:"title"`
	Content string `json:"content"`
}

type documentPatchRequest struct {
	Title   *string `json:"title"`
	Content *string `json:"content"`
}

func documentPathIDs(r *http.Request) (uuid.UUID, uuid.UUID, error) {
	organizationID, err := pathUUID(r, "organization_id")
	if err != nil {
		return uuid.Nil, uuid.Nil, err
	}
	documentID, err := pathUUID(r, "document_id")
	if err != nil {
		return uuid.Nil, uuid.Nil, err
	}
	return organizationID, documentID, nil
}

func pathUUID(r *http.Request, name string) (uuid.UUID, error) {
	value := strings.TrimSpace(r.PathValue(name))
	return uuid.Parse(value)
}

func writeResourceError(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, resources.ErrInvalidInput):
		writeError(w, http.StatusBadRequest, "invalid_input", "resource input is invalid", r)
	case errors.Is(err, resources.ErrOrganizationSlugExists):
		writeError(w, http.StatusConflict, "organization_slug_exists", "organization slug is already registered", r)
	case errors.Is(err, resources.ErrOrganizationNotFound), errors.Is(err, resources.ErrDocumentNotFound):
		// Do not disclose whether the resource exists in another organization.
		writeError(w, http.StatusNotFound, "not_found", "resource not found", r)
	case errors.Is(err, resources.ErrForbidden):
		writeError(w, http.StatusForbidden, "forbidden", "the user is not authorized for this resource", r)
	default:
		writeError(w, http.StatusInternalServerError, "resource_operation_failed", "resource operation failed", r)
	}
}

func resourceErrorStatus(err error) int {
	switch {
	case errors.Is(err, resources.ErrInvalidInput):
		return http.StatusBadRequest
	case errors.Is(err, resources.ErrOrganizationSlugExists):
		return http.StatusConflict
	case errors.Is(err, resources.ErrOrganizationNotFound), errors.Is(err, resources.ErrDocumentNotFound):
		return http.StatusNotFound
	case errors.Is(err, resources.ErrForbidden):
		return http.StatusForbidden
	default:
		return http.StatusInternalServerError
	}
}
