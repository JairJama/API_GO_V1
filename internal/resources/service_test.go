package resources

import (
	"context"
	"errors"
	"testing"
	"time"

	"example.com/go-security-api/internal/access"
	"github.com/google/uuid"
)

type fakePermissionStore struct {
	permissions map[string]bool
}

func (f fakePermissionStore) EffectivePermissions(context.Context, uuid.UUID) (map[string]bool, error) {
	return f.permissions, nil
}

type fakeOrganizationStore struct{}

func (fakeOrganizationStore) CreateOrganization(context.Context, string, string, uuid.UUID) (Organization, error) {
	return Organization{}, nil
}

type fakeDocumentStore struct {
	document      Document
	visible       bool
	updated       bool
	deleted       bool
	updateTitle   string
	updateContent string
}

func (f *fakeDocumentStore) CreateDocument(context.Context, uuid.UUID, uuid.UUID, string, string) (Document, error) {
	return f.document, nil
}

func (f *fakeDocumentStore) FindVisibleDocument(context.Context, uuid.UUID, uuid.UUID, uuid.UUID) (Document, error) {
	if !f.visible {
		return Document{}, ErrDocumentNotFound
	}
	return f.document, nil
}

func (f *fakeDocumentStore) UpdateDocument(_ context.Context, _ uuid.UUID, _ uuid.UUID, _ uuid.UUID, title, content string) (Document, error) {
	f.updated = true
	f.updateTitle = title
	f.updateContent = content
	f.document.Title = title
	f.document.Content = content
	return f.document, nil
}

func (f *fakeDocumentStore) DeleteDocument(context.Context, uuid.UUID, uuid.UUID, uuid.UUID) (Document, error) {
	f.deleted = true
	return f.document, nil
}

func newResourceServiceForTest(store *fakeDocumentStore, permissions map[string]bool) *Service {
	authorization := access.NewService(fakePermissionStore{permissions: permissions})
	return NewService(fakeOrganizationStore{}, store, authorization)
}

func TestUpdateDocumentAllowsOwnerPermission(t *testing.T) {
	ownerID := uuid.New()
	store := &fakeDocumentStore{
		visible:  true,
		document: Document{ID: uuid.New(), OwnerID: ownerID, Title: "old", Content: "old", UpdatedAt: time.Now()},
	}
	service := newResourceServiceForTest(store, map[string]bool{"documents.update.own": true})
	title := "new title"

	updated, err := service.UpdateDocument(context.Background(), ownerID, uuid.New(), store.document.ID, &title, nil)
	if err != nil {
		t.Fatalf("update own document: %v", err)
	}
	if !store.updated || updated.Title != title {
		t.Fatalf("expected owner update, got %#v", updated)
	}
}

func TestUpdateDocumentDeniesNonOwnerWithOwnPermission(t *testing.T) {
	ownerID := uuid.New()
	store := &fakeDocumentStore{
		visible:  true,
		document: Document{ID: uuid.New(), OwnerID: ownerID, Title: "old"},
	}
	service := newResourceServiceForTest(store, map[string]bool{"documents.update.own": true})
	title := "new title"

	_, err := service.UpdateDocument(context.Background(), uuid.New(), uuid.New(), store.document.ID, &title, nil)
	if !errors.Is(err, ErrForbidden) {
		t.Fatalf("expected forbidden error, got %v", err)
	}
	if store.updated {
		t.Fatal("expected document not to be updated")
	}
}

func TestUpdateDocumentAllowsAnyPermissionForAnotherOwner(t *testing.T) {
	store := &fakeDocumentStore{
		visible:  true,
		document: Document{ID: uuid.New(), OwnerID: uuid.New(), Title: "old"},
	}
	service := newResourceServiceForTest(store, map[string]bool{"documents.update.any": true})
	content := "new content"

	if _, err := service.UpdateDocument(context.Background(), uuid.New(), uuid.New(), store.document.ID, nil, &content); err != nil {
		t.Fatalf("update any document: %v", err)
	}
	if !store.updated || store.updateContent != content {
		t.Fatal("expected any-permission update")
	}
}

func TestOtherOrganizationIsNotFound(t *testing.T) {
	store := &fakeDocumentStore{visible: false}
	service := newResourceServiceForTest(store, map[string]bool{"documents.read": true})

	_, err := service.FindDocument(context.Background(), uuid.New(), uuid.New(), uuid.New())
	if !errors.Is(err, ErrDocumentNotFound) {
		t.Fatalf("expected not found for inaccessible organization, got %v", err)
	}
}
