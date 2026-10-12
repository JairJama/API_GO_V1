package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"example.com/go-security-api/internal/serviceaccounts"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type ServiceAccountStore struct {
	database *pgxpool.Pool
}

func NewServiceAccountStore(database *pgxpool.Pool) *ServiceAccountStore {
	return &ServiceAccountStore{database: database}
}

func (s *ServiceAccountStore) CreateAccount(ctx context.Context, organizationID, createdBy uuid.UUID, name, slug string, roles []string) (serviceaccounts.Account, error) {
	tx, err := s.database.Begin(ctx)
	if err != nil {
		return serviceaccounts.Account{}, fmt.Errorf("begin service account transaction: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var account serviceaccounts.Account
	err = tx.QueryRow(ctx, `
		INSERT INTO service_accounts (organization_id, name, slug, created_by)
		SELECT $1, $2, $3, $4
		WHERE EXISTS (
			SELECT 1 FROM organization_users
			WHERE organization_id = $1 AND user_id = $4 AND status = 'active'
		)
		RETURNING id, organization_id, name, slug, status, created_by, created_at, updated_at
	`, organizationID, name, slug, createdBy).Scan(
		&account.ID, &account.OrganizationID, &account.Name, &account.Slug, &account.Status,
		&account.CreatedBy, &account.CreatedAt, &account.UpdatedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return serviceaccounts.Account{}, serviceaccounts.ErrNotFound
	}
	if err != nil {
		return serviceaccounts.Account{}, fmt.Errorf("create service account: %w", err)
	}

	command, err := tx.Exec(ctx, `
		INSERT INTO service_account_roles (service_account_id, role_id)
		SELECT $1, id FROM roles WHERE name = ANY($2)
		ON CONFLICT DO NOTHING
	`, account.ID, roles)
	if err != nil {
		return serviceaccounts.Account{}, fmt.Errorf("assign service account roles: %w", err)
	}
	if command.RowsAffected() != int64(len(roles)) {
		return serviceaccounts.Account{}, serviceaccounts.ErrInvalidInput
	}
	if err := tx.Commit(ctx); err != nil {
		return serviceaccounts.Account{}, fmt.Errorf("commit service account transaction: %w", err)
	}
	return account, nil
}

func (s *ServiceAccountStore) ListAccounts(ctx context.Context, organizationID, requesterID uuid.UUID) ([]serviceaccounts.Account, error) {
	allowed, err := s.memberOfOrganization(ctx, organizationID, requesterID)
	if err != nil {
		return nil, err
	}
	if !allowed {
		return nil, serviceaccounts.ErrNotFound
	}
	rows, err := s.database.Query(ctx, `
		SELECT id, organization_id, name, slug, status, created_by, created_at, updated_at
		FROM service_accounts WHERE organization_id = $1 ORDER BY created_at, id
	`, organizationID)
	if err != nil {
		return nil, fmt.Errorf("list service accounts: %w", err)
	}
	defer rows.Close()
	return scanAccounts(rows)
}

func (s *ServiceAccountStore) AccountPermissionsForManager(ctx context.Context, accountID, requesterID uuid.UUID) (serviceaccounts.Account, map[string]bool, error) {
	account, err := s.accountForManager(ctx, accountID, requesterID)
	if err != nil {
		return serviceaccounts.Account{}, nil, err
	}
	permissions, err := s.effectivePermissions(ctx, accountID)
	if err != nil {
		return serviceaccounts.Account{}, nil, err
	}
	return account, permissions, nil
}

func (s *ServiceAccountStore) CreateToken(ctx context.Context, token serviceaccounts.Token, tokenHash []byte) error {
	_, err := s.database.Exec(ctx, `
		INSERT INTO api_tokens (id, service_account_id, name, token_prefix, token_hash, abilities, expires_at, created_by)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
	`, token.ID, token.ServiceAccountID, token.Name, token.TokenPrefix, tokenHash, token.Scopes, token.ExpiresAt, token.CreatedBy)
	if err != nil {
		return fmt.Errorf("create api token: %w", err)
	}
	return nil
}

func (s *ServiceAccountStore) ListTokens(ctx context.Context, accountID, requesterID uuid.UUID) ([]serviceaccounts.Token, error) {
	if _, err := s.accountForManager(ctx, accountID, requesterID); err != nil {
		return nil, err
	}
	rows, err := s.database.Query(ctx, `
		SELECT id, service_account_id, name, token_prefix, abilities, last_used_at,
		       host(last_used_ip), expires_at, revoked_at, created_at, created_by
		FROM api_tokens WHERE service_account_id = $1 ORDER BY created_at DESC, id
	`, accountID)
	if err != nil {
		return nil, fmt.Errorf("list api tokens: %w", err)
	}
	defer rows.Close()
	return scanTokens(rows)
}

func (s *ServiceAccountStore) RevokeToken(ctx context.Context, accountID, tokenID, requesterID uuid.UUID) error {
	if _, err := s.accountForManager(ctx, accountID, requesterID); err != nil {
		return err
	}
	command, err := s.database.Exec(ctx, `
		UPDATE api_tokens SET revoked_at = COALESCE(revoked_at, NOW())
		WHERE id = $1 AND service_account_id = $2
	`, tokenID, accountID)
	if err != nil {
		return fmt.Errorf("revoke api token: %w", err)
	}
	if command.RowsAffected() == 0 {
		return serviceaccounts.ErrNotFound
	}
	return nil
}

func (s *ServiceAccountStore) FindToken(ctx context.Context, tokenID uuid.UUID) (serviceaccounts.TokenAuthentication, error) {
	var result serviceaccounts.TokenAuthentication
	err := s.database.QueryRow(ctx, `
		SELECT t.id, t.service_account_id, t.name, t.token_prefix, t.abilities, t.last_used_at,
		       host(t.last_used_ip), t.expires_at, t.revoked_at, t.created_at, t.created_by, t.token_hash,
		       sa.id, sa.organization_id, sa.name, sa.slug, sa.status, sa.created_by, sa.created_at, sa.updated_at
		FROM api_tokens t JOIN service_accounts sa ON sa.id = t.service_account_id
		WHERE t.id = $1
	`, tokenID).Scan(
		&result.ID, &result.ServiceAccountID, &result.Name, &result.TokenPrefix, &result.Scopes, &result.LastUsedAt,
		&result.LastUsedIP, &result.ExpiresAt, &result.RevokedAt, &result.CreatedAt, &result.CreatedBy, &result.TokenHash,
		&result.Account.ID, &result.Account.OrganizationID, &result.Account.Name, &result.Account.Slug, &result.Account.Status,
		&result.Account.CreatedBy, &result.Account.CreatedAt, &result.Account.UpdatedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return serviceaccounts.TokenAuthentication{}, serviceaccounts.ErrNotFound
	}
	if err != nil {
		return serviceaccounts.TokenAuthentication{}, fmt.Errorf("find api token: %w", err)
	}
	permissions, err := s.effectivePermissions(ctx, result.Account.ID)
	if err != nil {
		return serviceaccounts.TokenAuthentication{}, err
	}
	result.Permissions = permissions
	return result, nil
}

func (s *ServiceAccountStore) MarkTokenUsed(ctx context.Context, tokenID uuid.UUID, ip string) error {
	_, err := s.database.Exec(ctx, `UPDATE api_tokens SET last_used_at = NOW(), last_used_ip = NULLIF($2, '')::inet WHERE id = $1`, tokenID, ip)
	if err != nil {
		return fmt.Errorf("update api token usage: %w", err)
	}
	return nil
}

func (s *ServiceAccountStore) accountForManager(ctx context.Context, accountID, requesterID uuid.UUID) (serviceaccounts.Account, error) {
	var account serviceaccounts.Account
	err := s.database.QueryRow(ctx, `
		SELECT sa.id, sa.organization_id, sa.name, sa.slug, sa.status, sa.created_by, sa.created_at, sa.updated_at
		FROM service_accounts sa
		JOIN organization_users ou ON ou.organization_id = sa.organization_id
		WHERE sa.id = $1 AND ou.user_id = $2 AND ou.status = 'active'
	`, accountID, requesterID).Scan(
		&account.ID, &account.OrganizationID, &account.Name, &account.Slug, &account.Status,
		&account.CreatedBy, &account.CreatedAt, &account.UpdatedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return serviceaccounts.Account{}, serviceaccounts.ErrNotFound
	}
	if err != nil {
		return serviceaccounts.Account{}, fmt.Errorf("find service account: %w", err)
	}
	return account, nil
}

func (s *ServiceAccountStore) memberOfOrganization(ctx context.Context, organizationID, userID uuid.UUID) (bool, error) {
	var allowed bool
	err := s.database.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM organization_users WHERE organization_id = $1 AND user_id = $2 AND status = 'active')`, organizationID, userID).Scan(&allowed)
	if err != nil {
		return false, fmt.Errorf("check organization membership: %w", err)
	}
	return allowed, nil
}

func (s *ServiceAccountStore) effectivePermissions(ctx context.Context, accountID uuid.UUID) (map[string]bool, error) {
	rows, err := s.database.Query(ctx, `
		SELECT DISTINCT p.name FROM permissions p
		WHERE EXISTS (
			SELECT 1 FROM role_permissions rp JOIN service_account_roles sar ON sar.role_id = rp.role_id
			WHERE sar.service_account_id = $1 AND rp.permission_id = p.id
		) OR EXISTS (
			SELECT 1 FROM service_account_permissions sap
			WHERE sap.service_account_id = $1 AND sap.permission_id = p.id
		)
		ORDER BY p.name
	`, accountID)
	if err != nil {
		return nil, fmt.Errorf("query service account permissions: %w", err)
	}
	defer rows.Close()
	permissions := make(map[string]bool)
	for rows.Next() {
		var permission string
		if err := rows.Scan(&permission); err != nil {
			return nil, fmt.Errorf("scan service account permission: %w", err)
		}
		permissions[permission] = true
	}
	return permissions, rows.Err()
}

func scanAccounts(rows pgx.Rows) ([]serviceaccounts.Account, error) {
	accounts := []serviceaccounts.Account{}
	for rows.Next() {
		var account serviceaccounts.Account
		if err := rows.Scan(&account.ID, &account.OrganizationID, &account.Name, &account.Slug, &account.Status, &account.CreatedBy, &account.CreatedAt, &account.UpdatedAt); err != nil {
			return nil, fmt.Errorf("scan service account: %w", err)
		}
		accounts = append(accounts, account)
	}
	return accounts, rows.Err()
}

func scanTokens(rows pgx.Rows) ([]serviceaccounts.Token, error) {
	tokens := []serviceaccounts.Token{}
	for rows.Next() {
		var token serviceaccounts.Token
		if err := rows.Scan(&token.ID, &token.ServiceAccountID, &token.Name, &token.TokenPrefix, &token.Scopes, &token.LastUsedAt, &token.LastUsedIP, &token.ExpiresAt, &token.RevokedAt, &token.CreatedAt, &token.CreatedBy); err != nil {
			return nil, fmt.Errorf("scan api token: %w", err)
		}
		tokens = append(tokens, token)
	}
	return tokens, rows.Err()
}

var _ = time.Time{}
