package serviceaccounts

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"example.com/go-security-api/internal/principal"
	"github.com/google/uuid"
)

var (
	ErrInvalidInput    = errors.New("invalid service account input")
	ErrNotFound        = errors.New("service account not found")
	ErrForbidden       = errors.New("service account access forbidden")
	ErrUnauthenticated = errors.New("invalid api token")
)

type Account struct {
	ID             uuid.UUID `json:"id"`
	OrganizationID uuid.UUID `json:"organization_id"`
	Name           string    `json:"name"`
	Slug           string    `json:"slug"`
	Status         string    `json:"status"`
	CreatedBy      uuid.UUID `json:"created_by"`
	CreatedAt      time.Time `json:"created_at"`
	UpdatedAt      time.Time `json:"updated_at"`
}

type Token struct {
	ID               uuid.UUID  `json:"id"`
	ServiceAccountID uuid.UUID  `json:"service_account_id"`
	Name             string     `json:"name"`
	TokenPrefix      string     `json:"token_prefix"`
	Scopes           []string   `json:"scopes"`
	LastUsedAt       *time.Time `json:"last_used_at"`
	LastUsedIP       *string    `json:"last_used_ip"`
	ExpiresAt        time.Time  `json:"expires_at"`
	RevokedAt        *time.Time `json:"revoked_at"`
	CreatedAt        time.Time  `json:"created_at"`
	CreatedBy        uuid.UUID  `json:"created_by"`
}

type TokenAuthentication struct {
	Token
	TokenHash   []byte
	Account     Account
	Permissions map[string]bool
}

type Store interface {
	CreateAccount(context.Context, uuid.UUID, uuid.UUID, string, string, []string) (Account, error)
	ListAccounts(context.Context, uuid.UUID, uuid.UUID) ([]Account, error)
	AccountPermissionsForManager(context.Context, uuid.UUID, uuid.UUID) (Account, map[string]bool, error)
	CreateToken(context.Context, Token, []byte) error
	ListTokens(context.Context, uuid.UUID, uuid.UUID) ([]Token, error)
	RevokeToken(context.Context, uuid.UUID, uuid.UUID, uuid.UUID) error
	FindToken(context.Context, uuid.UUID) (TokenAuthentication, error)
	MarkTokenUsed(context.Context, uuid.UUID, string) error
}

type Service struct {
	store  Store
	pepper []byte
	maxTTL time.Duration
	now    func() time.Time
}

func NewService(store Store, pepper string) (*Service, error) {
	if store == nil || strings.TrimSpace(pepper) == "" {
		return nil, errors.New("service account store and API token pepper are required")
	}
	return &Service{store: store, pepper: []byte(pepper), maxTTL: 30 * 24 * time.Hour, now: func() time.Time { return time.Now().UTC() }}, nil
}

func (s *Service) CreateAccount(ctx context.Context, organizationID, createdBy uuid.UUID, name, slug string, roles []string) (Account, error) {
	name, slug = strings.TrimSpace(name), strings.ToLower(strings.TrimSpace(slug))
	if name == "" || len(name) > 200 || slug == "" || len(slug) > 100 || strings.ContainsAny(slug, " /\\") || len(roles) == 0 {
		return Account{}, ErrInvalidInput
	}
	return s.store.CreateAccount(ctx, organizationID, createdBy, name, slug, unique(roles))
}

func (s *Service) ListAccounts(ctx context.Context, organizationID, requesterID uuid.UUID) ([]Account, error) {
	return s.store.ListAccounts(ctx, organizationID, requesterID)
}

func (s *Service) IssueToken(ctx context.Context, accountID, createdBy uuid.UUID, name string, scopes []string, expiresAt time.Time) (Token, string, error) {
	name = strings.TrimSpace(name)
	now := s.now()
	if name == "" || len(name) > 200 || !expiresAt.After(now) || expiresAt.After(now.Add(s.maxTTL)) || len(scopes) == 0 {
		return Token{}, "", ErrInvalidInput
	}
	scopes = unique(scopes)
	for _, scope := range scopes {
		if scope == "*" || strings.TrimSpace(scope) == "" {
			return Token{}, "", ErrInvalidInput
		}
	}
	account, permissions, err := s.store.AccountPermissionsForManager(ctx, accountID, createdBy)
	if err != nil {
		return Token{}, "", err
	}
	for _, scope := range scopes {
		if !permissions[scope] {
			return Token{}, "", ErrForbidden
		}
	}
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return Token{}, "", fmt.Errorf("generate api token secret: %w", err)
	}
	id := uuid.New()
	raw := "atk_" + id.String() + "_" + base64.RawURLEncoding.EncodeToString(secret)
	token := Token{ID: id, ServiceAccountID: account.ID, Name: name, TokenPrefix: "atk_" + id.String(), Scopes: scopes, ExpiresAt: expiresAt.UTC(), CreatedBy: createdBy}
	if err := s.store.CreateToken(ctx, token, s.hash(raw)); err != nil {
		return Token{}, "", err
	}
	return token, raw, nil
}

func (s *Service) ListTokens(ctx context.Context, accountID, requesterID uuid.UUID) ([]Token, error) {
	return s.store.ListTokens(ctx, accountID, requesterID)
}

func (s *Service) RevokeToken(ctx context.Context, accountID, tokenID, requesterID uuid.UUID) error {
	return s.store.RevokeToken(ctx, accountID, tokenID, requesterID)
}

func (s *Service) Authenticate(ctx context.Context, raw, ip string) (principal.Principal, error) {
	id, err := parseToken(raw)
	if err != nil {
		return principal.Principal{}, ErrUnauthenticated
	}
	value, err := s.store.FindToken(ctx, id)
	if err != nil || subtle.ConstantTimeCompare(s.hash(raw), value.TokenHash) != 1 || value.RevokedAt != nil || !s.now().Before(value.ExpiresAt) || value.Account.Status != "active" {
		return principal.Principal{}, ErrUnauthenticated
	}
	for scope := range mapFromSlice(value.Scopes) {
		if !value.Permissions[scope] {
			return principal.Principal{}, ErrUnauthenticated
		}
	}
	if net.ParseIP(ip) == nil {
		ip = ""
	}
	if err := s.store.MarkTokenUsed(ctx, id, ip); err != nil {
		return principal.Principal{}, fmt.Errorf("mark api token as used: %w", err)
	}
	return principal.Principal{Type: principal.ServiceAccount, ID: value.Account.ID, OrganizationID: value.Account.OrganizationID, Permissions: value.Permissions, Scopes: mapFromSlice(value.Scopes), TokenID: &id}, nil
}

func (s *Service) hash(value string) []byte {
	mac := hmac.New(sha256.New, s.pepper)
	_, _ = mac.Write([]byte(value))
	return mac.Sum(nil)
}

func parseToken(raw string) (uuid.UUID, error) {
	parts := strings.SplitN(raw, "_", 3)
	if len(parts) != 3 || parts[0] != "atk" {
		return uuid.Nil, ErrUnauthenticated
	}
	id, err := uuid.Parse(parts[1])
	if err != nil {
		return uuid.Nil, ErrUnauthenticated
	}
	secret, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || len(secret) != 32 {
		return uuid.Nil, ErrUnauthenticated
	}
	return id, nil
}

func unique(values []string) []string {
	seen := make(map[string]bool, len(values))
	result := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" && !seen[value] {
			seen[value] = true
			result = append(result, value)
		}
	}
	return result
}

func mapFromSlice(values []string) map[string]bool {
	result := make(map[string]bool, len(values))
	for _, value := range values {
		result[value] = true
	}
	return result
}
