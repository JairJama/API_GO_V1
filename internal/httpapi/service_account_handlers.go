package httpapi

import (
	"errors"
	"net/http"
	"time"

	"example.com/go-security-api/internal/access"
	"example.com/go-security-api/internal/audit"
	"example.com/go-security-api/internal/auth"
	"example.com/go-security-api/internal/serviceaccounts"
)

func registerServiceAccountRoutes(mux *http.ServeMux, authentication *auth.Service, tokens *serviceaccounts.Service, authorization *access.Service, auditor *audit.Service) {
	human := func(permission string, next http.Handler) http.Handler {
		return AuthenticatePrincipal(authentication, tokens, auditor, requireHumanPrincipal(auditor, requirePermission(authorization, auditor, permission, next)))
	}
	mux.Handle("POST /api/v1/organizations/{organization_id}/service-accounts", human("service_accounts.manage", http.HandlerFunc(createServiceAccountHandler(tokens, auditor))))
	mux.Handle("GET /api/v1/organizations/{organization_id}/service-accounts", human("service_accounts.manage", http.HandlerFunc(listServiceAccountsHandler(tokens, auditor))))
	mux.Handle("POST /api/v1/service-accounts/{service_account_id}/tokens", human("api_tokens.issue", http.HandlerFunc(issueTokenHandler(tokens, auditor))))
	mux.Handle("GET /api/v1/service-accounts/{service_account_id}/tokens", human("api_tokens.issue", http.HandlerFunc(listTokensHandler(tokens, auditor))))
	mux.Handle("DELETE /api/v1/service-accounts/{service_account_id}/tokens/{token_id}", human("api_tokens.revoke", http.HandlerFunc(revokeTokenHandler(tokens, auditor))))
}

type serviceAccountRequest struct {
	Name  string   `json:"name"`
	Slug  string   `json:"slug"`
	Roles []string `json:"roles"`
}

type apiTokenRequest struct {
	Name      string   `json:"name"`
	Scopes    []string `json:"scopes"`
	ExpiresAt string   `json:"expires_at"`
}

func createServiceAccountHandler(service *serviceaccounts.Service, auditor *audit.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user, ok := auth.UserFromContext(r.Context())
		if !ok || service == nil {
			writeError(w, http.StatusServiceUnavailable, "service_accounts_unavailable", "service accounts are not configured", r)
			return
		}
		organizationID, err := pathUUID(r, "organization_id")
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid_organization_id", "organization id is invalid", r)
			return
		}
		var input serviceAccountRequest
		if err := decodeJSON(w, r, &input); err != nil {
			writeError(w, http.StatusBadRequest, "invalid_json", "request body is invalid", r)
			return
		}
		account, err := service.CreateAccount(r.Context(), organizationID, user.ID, input.Name, input.Slug, input.Roles)
		if err != nil {
			recordAuditForUser(auditor, r, user, "service_account.created", outcomeForStatus(serviceAccountStatus(err)), serviceAccountStatus(err), "service_account", nil, map[string]any{"organization_id": organizationID.String()})
			writeServiceAccountError(w, r, err)
			return
		}
		recordAuditForUser(auditor, r, user, "service_account.created", "success", http.StatusCreated, "service_account", &account.ID, map[string]any{"organization_id": organizationID.String()})
		writeJSON(w, http.StatusCreated, account)
	}
}

func listServiceAccountsHandler(service *serviceaccounts.Service, auditor *audit.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user, ok := auth.UserFromContext(r.Context())
		if !ok || service == nil {
			writeError(w, http.StatusServiceUnavailable, "service_accounts_unavailable", "service accounts are not configured", r)
			return
		}
		organizationID, err := pathUUID(r, "organization_id")
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid_organization_id", "organization id is invalid", r)
			return
		}
		accounts, err := service.ListAccounts(r.Context(), organizationID, user.ID)
		if err != nil {
			writeServiceAccountError(w, r, err)
			return
		}
		writeJSON(w, http.StatusOK, accounts)
	}
}

func issueTokenHandler(service *serviceaccounts.Service, auditor *audit.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user, ok := auth.UserFromContext(r.Context())
		if !ok || service == nil {
			writeError(w, http.StatusServiceUnavailable, "service_accounts_unavailable", "service accounts are not configured", r)
			return
		}
		accountID, err := pathUUID(r, "service_account_id")
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid_service_account_id", "service account id is invalid", r)
			return
		}
		var input apiTokenRequest
		if err := decodeJSON(w, r, &input); err != nil {
			writeError(w, http.StatusBadRequest, "invalid_json", "request body is invalid", r)
			return
		}
		expiresAt, err := time.Parse(time.RFC3339, input.ExpiresAt)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid_input", "token expiry is invalid", r)
			return
		}
		token, raw, err := service.IssueToken(r.Context(), accountID, user.ID, input.Name, input.Scopes, expiresAt)
		if err != nil {
			recordAuditForUser(auditor, r, user, "api_token.issued", outcomeForStatus(serviceAccountStatus(err)), serviceAccountStatus(err), "service_account", &accountID, nil)
			writeServiceAccountError(w, r, err)
			return
		}
		recordAuditForUser(auditor, r, user, "api_token.issued", "success", http.StatusCreated, "service_account", &accountID, nil)
		writeJSON(w, http.StatusCreated, map[string]any{"token": raw, "metadata": token})
	}
}

func listTokensHandler(service *serviceaccounts.Service, auditor *audit.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user, ok := auth.UserFromContext(r.Context())
		if !ok || service == nil {
			writeError(w, http.StatusServiceUnavailable, "service_accounts_unavailable", "service accounts are not configured", r)
			return
		}
		accountID, err := pathUUID(r, "service_account_id")
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid_service_account_id", "service account id is invalid", r)
			return
		}
		tokens, err := service.ListTokens(r.Context(), accountID, user.ID)
		if err != nil {
			writeServiceAccountError(w, r, err)
			return
		}
		writeJSON(w, http.StatusOK, tokens)
	}
}

func revokeTokenHandler(service *serviceaccounts.Service, auditor *audit.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user, ok := auth.UserFromContext(r.Context())
		if !ok || service == nil {
			writeError(w, http.StatusServiceUnavailable, "service_accounts_unavailable", "service accounts are not configured", r)
			return
		}
		accountID, err := pathUUID(r, "service_account_id")
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid_service_account_id", "service account id is invalid", r)
			return
		}
		tokenID, err := pathUUID(r, "token_id")
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid_token_id", "token id is invalid", r)
			return
		}
		if err := service.RevokeToken(r.Context(), accountID, tokenID, user.ID); err != nil {
			writeServiceAccountError(w, r, err)
			return
		}
		recordAuditForUser(auditor, r, user, "api_token.revoked", "success", http.StatusNoContent, "service_account", &accountID, nil)
		w.WriteHeader(http.StatusNoContent)
	}
}

func writeServiceAccountError(w http.ResponseWriter, r *http.Request, err error) {
	status := serviceAccountStatus(err)
	message := "service account operation failed"
	if status == http.StatusBadRequest {
		message = "service account input is invalid"
	} else if status == http.StatusForbidden {
		message = "the requested token scope is not permitted"
	} else if status == http.StatusNotFound {
		message = "service account not found"
	}
	writeError(w, status, "service_account_operation_failed", message, r)
}

func serviceAccountStatus(err error) int {
	switch {
	case errors.Is(err, serviceaccounts.ErrInvalidInput):
		return http.StatusBadRequest
	case errors.Is(err, serviceaccounts.ErrForbidden):
		return http.StatusForbidden
	case errors.Is(err, serviceaccounts.ErrNotFound):
		return http.StatusNotFound
	default:
		return http.StatusInternalServerError
	}
}
