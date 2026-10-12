package principal

import (
	"context"

	"github.com/google/uuid"
)

const (
	Human          = "human"
	ServiceAccount = "service_account"
)

type Principal struct {
	Type           string
	ID             uuid.UUID
	OrganizationID uuid.UUID
	Permissions    map[string]bool
	Scopes         map[string]bool
	TokenID        *uuid.UUID
}

func (p Principal) Has(permission string) bool {
	if !p.Permissions[permission] {
		return false
	}
	return p.Type != ServiceAccount || p.Scopes[permission]
}

type contextKey struct{}

func With(ctx context.Context, value Principal) context.Context {
	return context.WithValue(ctx, contextKey{}, value)
}

func FromContext(ctx context.Context) (Principal, bool) {
	value, ok := ctx.Value(contextKey{}).(Principal)
	return value, ok
}
