package postgres

import (
	"context"
	"errors"
	"fmt"

	"example.com/go-security-api/internal/resources"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

type OrganizationStore struct {
	database *pgxpool.Pool
}

func NewOrganizationStore(database *pgxpool.Pool) *OrganizationStore {
	return &OrganizationStore{database: database}
}

func (s *OrganizationStore) CreateOrganization(ctx context.Context, name, slug string, ownerID uuid.UUID) (resources.Organization, error) {
	tx, err := s.database.Begin(ctx)
	if err != nil {
		return resources.Organization{}, fmt.Errorf("begin organization transaction: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var organization resources.Organization
	err = tx.QueryRow(ctx, `
		INSERT INTO organizations (name, slug, owner_id)
		VALUES ($1, $2, $3)
		RETURNING id, name, slug, owner_id, created_at, updated_at
	`, name, slug, ownerID).Scan(
		&organization.ID, &organization.Name, &organization.Slug, &organization.OwnerID,
		&organization.CreatedAt, &organization.UpdatedAt,
	)
	if err != nil {
		var pgError *pgconn.PgError
		if errors.As(err, &pgError) && pgError.Code == "23505" {
			return resources.Organization{}, resources.ErrOrganizationSlugExists
		}
		return resources.Organization{}, fmt.Errorf("create organization: %w", err)
	}

	if _, err := tx.Exec(ctx, `
		INSERT INTO organization_users (organization_id, user_id, status)
		VALUES ($1, $2, 'active')
	`, organization.ID, ownerID); err != nil {
		return resources.Organization{}, fmt.Errorf("assign organization owner: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return resources.Organization{}, fmt.Errorf("commit organization transaction: %w", err)
	}
	return organization, nil
}

type DocumentStore struct {
	database *pgxpool.Pool
}

func NewDocumentStore(database *pgxpool.Pool) *DocumentStore {
	return &DocumentStore{database: database}
}

func (s *DocumentStore) CreateDocument(ctx context.Context, organizationID, ownerID uuid.UUID, title, content string) (resources.Document, error) {
	var document resources.Document
	err := s.database.QueryRow(ctx, `
		INSERT INTO documents (organization_id, owner_id, title, content)
		SELECT $1, $2, $3, $4
		WHERE EXISTS (
			SELECT 1
			FROM organization_users
			WHERE organization_id = $1 AND user_id = $2 AND status = 'active'
		)
		RETURNING id, organization_id, owner_id, title, content, created_at, updated_at
	`, organizationID, ownerID, title, content).Scan(
		&document.ID, &document.OrganizationID, &document.OwnerID, &document.Title, &document.Content,
		&document.CreatedAt, &document.UpdatedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return resources.Document{}, resources.ErrOrganizationNotFound
	}
	if err != nil {
		return resources.Document{}, fmt.Errorf("create document: %w", err)
	}
	return document, nil
}

func (s *DocumentStore) FindVisibleDocument(ctx context.Context, organizationID, documentID, userID uuid.UUID) (resources.Document, error) {
	var document resources.Document
	err := s.database.QueryRow(ctx, `
		SELECT d.id, d.organization_id, d.owner_id, d.title, d.content, d.created_at, d.updated_at
		FROM documents d
		JOIN organization_users ou ON ou.organization_id = d.organization_id
		WHERE d.id = $1
		  AND d.organization_id = $2
		  AND ou.user_id = $3
		  AND ou.status = 'active'
	`, documentID, organizationID, userID).Scan(
		&document.ID, &document.OrganizationID, &document.OwnerID, &document.Title, &document.Content,
		&document.CreatedAt, &document.UpdatedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return resources.Document{}, resources.ErrDocumentNotFound
	}
	if err != nil {
		return resources.Document{}, fmt.Errorf("find visible document: %w", err)
	}
	return document, nil
}

func (s *DocumentStore) UpdateDocument(ctx context.Context, organizationID, documentID, userID uuid.UUID, title, content string) (resources.Document, error) {
	var document resources.Document
	err := s.database.QueryRow(ctx, `
		UPDATE documents d
		SET title = $3, content = $4, updated_at = NOW()
		WHERE d.id = $1
		  AND d.organization_id = $2
		  AND EXISTS (
			SELECT 1
			FROM organization_users ou
			WHERE ou.organization_id = d.organization_id
			  AND ou.user_id = $5
			  AND ou.status = 'active'
		  )
		RETURNING d.id, d.organization_id, d.owner_id, d.title, d.content, d.created_at, d.updated_at
	`, documentID, organizationID, title, content, userID).Scan(
		&document.ID, &document.OrganizationID, &document.OwnerID, &document.Title, &document.Content,
		&document.CreatedAt, &document.UpdatedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return resources.Document{}, resources.ErrDocumentNotFound
	}
	if err != nil {
		return resources.Document{}, fmt.Errorf("update document: %w", err)
	}
	return document, nil
}

func (s *DocumentStore) DeleteDocument(ctx context.Context, organizationID, documentID, userID uuid.UUID) (resources.Document, error) {
	var document resources.Document
	err := s.database.QueryRow(ctx, `
		DELETE FROM documents d
		WHERE d.id = $1
		  AND d.organization_id = $2
		  AND EXISTS (
			SELECT 1
			FROM organization_users ou
			WHERE ou.organization_id = d.organization_id
			  AND ou.user_id = $3
			  AND ou.status = 'active'
		  )
		RETURNING d.id, d.organization_id, d.owner_id, d.title, d.content, d.created_at, d.updated_at
	`, documentID, organizationID, userID).Scan(
		&document.ID, &document.OrganizationID, &document.OwnerID, &document.Title, &document.Content,
		&document.CreatedAt, &document.UpdatedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return resources.Document{}, resources.ErrDocumentNotFound
	}
	if err != nil {
		return resources.Document{}, fmt.Errorf("delete document: %w", err)
	}
	return document, nil
}
