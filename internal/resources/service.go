package resources

import (
	"context"
	"errors"
	"strings"

	"example.com/go-security-api/internal/access"
	"github.com/google/uuid"
)

var (
	ErrInvalidInput           = errors.New("invalid resource input")
	ErrOrganizationNotFound   = errors.New("organization not found")
	ErrOrganizationSlugExists = errors.New("organization slug already exists")
	ErrDocumentNotFound       = errors.New("document not found")
	ErrForbidden              = errors.New("resource access forbidden")
)

type OrganizationStore interface {
	CreateOrganization(ctx context.Context, name, slug string, ownerID uuid.UUID) (Organization, error)
}

type DocumentStore interface {
	CreateDocument(ctx context.Context, organizationID, ownerID uuid.UUID, title, content string) (Document, error)
	FindVisibleDocument(ctx context.Context, organizationID, documentID, userID uuid.UUID) (Document, error)
	UpdateDocument(ctx context.Context, organizationID, documentID, userID uuid.UUID, title, content string) (Document, error)
	DeleteDocument(ctx context.Context, organizationID, documentID, userID uuid.UUID) (Document, error)
}

type Service struct {
	organizations OrganizationStore
	documents     DocumentStore
	authorization *access.Service
}

func NewService(organizations OrganizationStore, documents DocumentStore, authorization *access.Service) *Service {
	return &Service{
		organizations: organizations,
		documents:     documents,
		authorization: authorization,
	}
}

func (s *Service) CreateOrganization(ctx context.Context, ownerID uuid.UUID, name, slug string) (Organization, error) {
	name = strings.TrimSpace(name)
	slug = strings.ToLower(strings.TrimSpace(slug))
	if name == "" || slug == "" || len(name) > 200 || len(slug) > 100 || strings.ContainsAny(slug, " /\\") {
		return Organization{}, ErrInvalidInput
	}
	if s.organizations == nil {
		return Organization{}, errors.New("organization store is not configured")
	}
	return s.organizations.CreateOrganization(ctx, name, slug, ownerID)
}

func (s *Service) CreateDocument(ctx context.Context, userID, organizationID uuid.UUID, title, content string) (Document, error) {
	title = strings.TrimSpace(title)
	if title == "" || len(title) > 200 || len(content) > 100000 {
		return Document{}, ErrInvalidInput
	}
	if err := s.requirePermission(ctx, userID, "documents.create"); err != nil {
		return Document{}, err
	}
	if s.documents == nil {
		return Document{}, errors.New("document store is not configured")
	}
	return s.documents.CreateDocument(ctx, organizationID, userID, title, content)
}

func (s *Service) FindDocument(ctx context.Context, userID, organizationID, documentID uuid.UUID) (Document, error) {
	if err := s.requirePermission(ctx, userID, "documents.read"); err != nil {
		return Document{}, err
	}
	if s.documents == nil {
		return Document{}, errors.New("document store is not configured")
	}
	return s.documents.FindVisibleDocument(ctx, organizationID, documentID, userID)
}

func (s *Service) UpdateDocument(ctx context.Context, userID, organizationID, documentID uuid.UUID, title, content *string) (Document, error) {
	if title == nil && content == nil {
		return Document{}, ErrInvalidInput
	}
	if s.documents == nil {
		return Document{}, errors.New("document store is not configured")
	}

	current, err := s.documents.FindVisibleDocument(ctx, organizationID, documentID, userID)
	if err != nil {
		return Document{}, err
	}

	permissions, err := s.effectivePermissions(ctx, userID)
	if err != nil {
		return Document{}, err
	}
	if !permissions["documents.update.any"] && !(permissions["documents.update.own"] && current.OwnerID == userID) {
		return Document{}, ErrForbidden
	}

	nextTitle := current.Title
	if title != nil {
		nextTitle = strings.TrimSpace(*title)
	}
	nextContent := current.Content
	if content != nil {
		nextContent = *content
	}
	if nextTitle == "" || len(nextTitle) > 200 || len(nextContent) > 100000 {
		return Document{}, ErrInvalidInput
	}

	return s.documents.UpdateDocument(ctx, organizationID, documentID, userID, nextTitle, nextContent)
}

func (s *Service) DeleteDocument(ctx context.Context, userID, organizationID, documentID uuid.UUID) (Document, error) {
	if s.documents == nil {
		return Document{}, errors.New("document store is not configured")
	}

	current, err := s.documents.FindVisibleDocument(ctx, organizationID, documentID, userID)
	if err != nil {
		return Document{}, err
	}

	permissions, err := s.effectivePermissions(ctx, userID)
	if err != nil {
		return Document{}, err
	}
	if !permissions["documents.delete.any"] && !(permissions["documents.delete.own"] && current.OwnerID == userID) {
		return Document{}, ErrForbidden
	}

	return s.documents.DeleteDocument(ctx, organizationID, documentID, userID)
}

func (s *Service) requirePermission(ctx context.Context, userID uuid.UUID, permission string) error {
	permissions, err := s.effectivePermissions(ctx, userID)
	if err != nil {
		return err
	}
	if !permissions[permission] {
		return ErrForbidden
	}
	return nil
}

func (s *Service) effectivePermissions(ctx context.Context, userID uuid.UUID) (map[string]bool, error) {
	if s.authorization == nil {
		return nil, errors.New("authorization service is not configured")
	}
	return s.authorization.Permissions(ctx, userID)
}
