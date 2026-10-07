package audit

import (
	"context"
	"testing"
)

type fakeStore struct {
	entry Entry
}

func (f *fakeStore) Append(_ context.Context, entry Entry) error {
	f.entry = entry
	return nil
}

func TestRecordAppliesSafeDefaults(t *testing.T) {
	store := &fakeStore{}
	service := NewService(store)

	if err := service.Record(context.Background(), Entry{Action: "test"}); err != nil {
		t.Fatalf("record audit entry: %v", err)
	}
	if store.entry.ActorType != "anonymous" {
		t.Fatalf("expected anonymous actor, got %q", store.entry.ActorType)
	}
	if store.entry.Metadata == nil {
		t.Fatal("expected non-nil metadata")
	}
	if store.entry.CreatedAt.IsZero() {
		t.Fatal("expected created timestamp")
	}
}
