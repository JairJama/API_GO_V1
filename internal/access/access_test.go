package access

import (
	"context"
	"testing"

	"github.com/google/uuid"
)

type fakePermissionStore struct {
	permissions map[string]bool
}

func (f fakePermissionStore) EffectivePermissions(context.Context, uuid.UUID) (map[string]bool, error) {
	return f.permissions, nil
}

func TestHasReturnsEffectivePermission(t *testing.T) {
	service := NewService(fakePermissionStore{permissions: map[string]bool{
		"users.read": true,
	}})

	allowed, err := service.Has(context.Background(), uuid.New(), "users.read")
	if err != nil {
		t.Fatalf("check permission: %v", err)
	}
	if !allowed {
		t.Fatal("expected permission to be allowed")
	}

	allowed, err = service.Has(context.Background(), uuid.New(), "users.manage")
	if err != nil {
		t.Fatalf("check missing permission: %v", err)
	}
	if allowed {
		t.Fatal("expected missing permission to be denied")
	}
}
