package migrations

import "testing"

func TestMigrationFilesAreEmbeddedAndOrdered(t *testing.T) {
	files, err := Files()
	if err != nil {
		t.Fatalf("list embedded migrations: %v", err)
	}
	if len(files) != 4 || files[0] != "sql/001_initial.sql" || files[1] != "sql/002_sessions.sql" || files[2] != "sql/003_rbac.sql" || files[3] != "sql/004_audit_logs.sql" {
		t.Fatalf("unexpected migrations: %#v", files)
	}
}
