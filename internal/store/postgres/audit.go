package postgres

import (
	"context"
	"encoding/json"
	"fmt"

	"example.com/go-security-api/internal/audit"
	"github.com/jackc/pgx/v5/pgxpool"
)

type AuditStore struct {
	database *pgxpool.Pool
}

func NewAuditStore(database *pgxpool.Pool) *AuditStore {
	return &AuditStore{database: database}
}

func (s *AuditStore) Append(ctx context.Context, entry audit.Entry) error {
	metadata, err := json.Marshal(entry.Metadata)
	if err != nil {
		return fmt.Errorf("marshal audit metadata: %w", err)
	}

	_, err = s.database.Exec(ctx, `
		INSERT INTO audit_logs (
			request_id, actor_type, actor_id, action, outcome,
			http_method, route, status_code, resource_type, resource_id, metadata, created_at
		)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11::jsonb, $12)
	`, entry.RequestID, entry.ActorType, entry.ActorID, entry.Action, entry.Outcome,
		entry.HTTPMethod, entry.Route, entry.StatusCode, entry.ResourceType, entry.ResourceID, metadata, entry.CreatedAt)
	if err != nil {
		return fmt.Errorf("append audit log: %w", err)
	}
	return nil
}
