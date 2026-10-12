package serviceaccounts

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
)

type fakeStore struct {
	account     Account
	permissions map[string]bool
	tokens      map[uuid.UUID]TokenAuthentication
	used        uuid.UUID
}

func (f *fakeStore) CreateAccount(context.Context, uuid.UUID, uuid.UUID, string, string, []string) (Account, error) {
	return f.account, nil
}
func (f *fakeStore) ListAccounts(context.Context, uuid.UUID, uuid.UUID) ([]Account, error) {
	return nil, nil
}
func (f *fakeStore) AccountPermissionsForManager(context.Context, uuid.UUID, uuid.UUID) (Account, map[string]bool, error) {
	return f.account, f.permissions, nil
}
func (f *fakeStore) CreateToken(_ context.Context, token Token, hash []byte) error {
	if f.tokens == nil {
		f.tokens = make(map[uuid.UUID]TokenAuthentication)
	}
	f.tokens[token.ID] = TokenAuthentication{Token: token, TokenHash: append([]byte(nil), hash...), Account: f.account, Permissions: f.permissions}
	return nil
}
func (f *fakeStore) ListTokens(context.Context, uuid.UUID, uuid.UUID) ([]Token, error) {
	return nil, nil
}
func (f *fakeStore) RevokeToken(context.Context, uuid.UUID, uuid.UUID, uuid.UUID) error { return nil }
func (f *fakeStore) FindToken(_ context.Context, id uuid.UUID) (TokenAuthentication, error) {
	token, ok := f.tokens[id]
	if !ok {
		return TokenAuthentication{}, ErrNotFound
	}
	return token, nil
}
func (f *fakeStore) MarkTokenUsed(_ context.Context, id uuid.UUID, _ string) error {
	f.used = id
	return nil
}

func TestIssuedTokenIsHMACHashedAndAuthenticates(t *testing.T) {
	now := time.Date(2026, 10, 12, 12, 0, 0, 0, time.UTC)
	account := Account{ID: uuid.New(), OrganizationID: uuid.New(), Status: "active"}
	store := &fakeStore{account: account, permissions: map[string]bool{"documents.read": true}}
	service, err := NewService(store, "test-pepper")
	if err != nil {
		t.Fatalf("new service: %v", err)
	}
	service.now = func() time.Time { return now }

	token, raw, err := service.IssueToken(context.Background(), account.ID, uuid.New(), "ERP", []string{"documents.read"}, now.Add(24*time.Hour))
	if err != nil {
		t.Fatalf("issue token: %v", err)
	}
	stored := store.tokens[token.ID]
	if string(stored.TokenHash) == raw {
		t.Fatal("token must not be stored in plaintext")
	}
	if string(stored.TokenHash) != string(service.hash(raw)) {
		t.Fatal("expected HMAC-SHA256 token hash")
	}
	actor, err := service.Authenticate(context.Background(), raw, "127.0.0.1")
	if err != nil {
		t.Fatalf("authenticate token: %v", err)
	}
	if actor.ID != account.ID || !actor.Has("documents.read") || store.used != token.ID {
		t.Fatalf("unexpected authenticated principal: %#v", actor)
	}
}

func TestTokenScopesAreRestrictedAndInvalidTokensFail(t *testing.T) {
	now := time.Date(2026, 10, 12, 12, 0, 0, 0, time.UTC)
	account := Account{ID: uuid.New(), OrganizationID: uuid.New(), Status: "active"}
	store := &fakeStore{account: account, permissions: map[string]bool{"documents.read": true}}
	service, _ := NewService(store, "test-pepper")
	service.now = func() time.Time { return now }
	if _, _, err := service.IssueToken(context.Background(), account.ID, uuid.New(), "ERP", []string{"documents.create"}, now.Add(time.Hour)); !errors.Is(err, ErrForbidden) {
		t.Fatalf("expected scope rejection, got %v", err)
	}
	token, raw, err := service.IssueToken(context.Background(), account.ID, uuid.New(), "ERP", []string{"documents.read"}, now.Add(time.Hour))
	if err != nil {
		t.Fatalf("issue token: %v", err)
	}
	stored := store.tokens[token.ID]
	stored.RevokedAt = &now
	store.tokens[token.ID] = stored
	if _, err := service.Authenticate(context.Background(), raw, "127.0.0.1"); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("expected revoked token to fail, got %v", err)
	}
	if _, err := service.Authenticate(context.Background(), "atk_not-a-uuid_secret", "127.0.0.1"); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("expected malformed token to fail, got %v", err)
	}
}
