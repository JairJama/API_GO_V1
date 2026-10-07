package postgres

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

type PermissionStore struct {
	database *pgxpool.Pool
}

func NewPermissionStore(database *pgxpool.Pool) *PermissionStore {
	return &PermissionStore{database: database}
}

func (s *PermissionStore) EffectivePermissions(ctx context.Context, userID uuid.UUID) (map[string]bool, error) {
	rows, err := s.database.Query(ctx, `
		SELECT DISTINCT p.name
		FROM permissions p
		WHERE EXISTS (
			SELECT 1
			FROM role_permissions rp
			JOIN user_roles ur ON ur.role_id = rp.role_id
			WHERE rp.permission_id = p.id AND ur.user_id = $1
		)
		OR EXISTS (
			SELECT 1
			FROM user_permissions up
			WHERE up.permission_id = p.id AND up.user_id = $1
		)
		ORDER BY p.name
	`, userID)
	if err != nil {
		return nil, fmt.Errorf("query effective permissions: %w", err)
	}
	defer rows.Close()

	permissions := make(map[string]bool)
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, fmt.Errorf("scan permission: %w", err)
		}
		permissions[name] = true
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate permissions: %w", err)
	}
	return permissions, nil
}
