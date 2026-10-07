package audit

import (
	"context"
	"time"

	"github.com/google/uuid"
)

type Entry struct {
	RequestID    string
	ActorType    string
	ActorID      *uuid.UUID
	Action       string
	Outcome      string
	HTTPMethod   string
	Route        string
	StatusCode   int
	ResourceType string
	ResourceID   *uuid.UUID
	Metadata     map[string]any
	CreatedAt    time.Time
}

type Store interface {
	Append(ctx context.Context, entry Entry) error
}

type Service struct {
	store Store
}

func NewService(store Store) *Service {
	return &Service{store: store}
}

func (s *Service) Record(ctx context.Context, entry Entry) error {
	if s == nil || s.store == nil {
		return nil
	}
	if entry.ActorType == "" {
		entry.ActorType = "anonymous"
	}
	if entry.Metadata == nil {
		entry.Metadata = map[string]any{}
	}
	if entry.CreatedAt.IsZero() {
		entry.CreatedAt = time.Now().UTC()
	}
	return s.store.Append(ctx, entry)
}
