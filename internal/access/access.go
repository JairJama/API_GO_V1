package access

import (
	"context"

	"github.com/google/uuid"
)

type PermissionStore interface {
	EffectivePermissions(ctx context.Context, userID uuid.UUID) (map[string]bool, error)
}

type Service struct {
	permissions PermissionStore
}

func NewService(permissions PermissionStore) *Service {
	return &Service{permissions: permissions}
}

func (s *Service) Permissions(ctx context.Context, userID uuid.UUID) (map[string]bool, error) {
	return s.permissions.EffectivePermissions(ctx, userID)
}

func (s *Service) Has(ctx context.Context, userID uuid.UUID, permission string) (bool, error) {
	permissions, err := s.Permissions(ctx, userID)
	if err != nil {
		return false, err
	}
	return permissions[permission], nil
}
