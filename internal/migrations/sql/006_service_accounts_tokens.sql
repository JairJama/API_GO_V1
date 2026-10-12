CREATE TABLE IF NOT EXISTS service_accounts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    slug TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'disabled')),
    created_by UUID NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (organization_id, slug)
);

CREATE TABLE IF NOT EXISTS service_account_roles (
    service_account_id UUID NOT NULL REFERENCES service_accounts(id) ON DELETE CASCADE,
    role_id UUID NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    granted_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (service_account_id, role_id)
);

CREATE TABLE IF NOT EXISTS service_account_permissions (
    service_account_id UUID NOT NULL REFERENCES service_accounts(id) ON DELETE CASCADE,
    permission_id UUID NOT NULL REFERENCES permissions(id) ON DELETE CASCADE,
    granted_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (service_account_id, permission_id)
);

CREATE TABLE IF NOT EXISTS api_tokens (
    id UUID PRIMARY KEY,
    service_account_id UUID NOT NULL REFERENCES service_accounts(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    token_prefix TEXT NOT NULL UNIQUE,
    token_hash BYTEA NOT NULL UNIQUE,
    abilities TEXT[] NOT NULL DEFAULT '{}',
    last_used_at TIMESTAMPTZ NULL,
    last_used_ip INET NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_by UUID NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    CHECK (array_position(abilities, '*') IS NULL)
);

CREATE INDEX IF NOT EXISTS idx_service_accounts_organization_id ON service_accounts (organization_id);
CREATE INDEX IF NOT EXISTS idx_api_tokens_service_account_id ON api_tokens (service_account_id);
CREATE INDEX IF NOT EXISTS idx_api_tokens_expires_at ON api_tokens (expires_at);

INSERT INTO permissions (name, description) VALUES
    ('service_accounts.manage', 'Administrar cuentas tecnicas'),
    ('api_tokens.issue', 'Emitir tokens de API'),
    ('api_tokens.revoke', 'Revocar tokens de API')
ON CONFLICT (name) DO NOTHING;

INSERT INTO roles (name, description) VALUES
    ('erp-reader', 'Lectura de documentos para integraciones ERP')
ON CONFLICT (name) DO NOTHING;

INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id
FROM roles r
JOIN permissions p ON p.name IN ('service_accounts.manage', 'api_tokens.issue', 'api_tokens.revoke')
WHERE r.name = 'admin'
ON CONFLICT DO NOTHING;

INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id
FROM roles r
JOIN permissions p ON p.name = 'documents.read'
WHERE r.name = 'erp-reader'
ON CONFLICT DO NOTHING;

ALTER TABLE audit_logs ADD COLUMN IF NOT EXISTS actor_service_account_id UUID NULL REFERENCES service_accounts(id) ON DELETE SET NULL;
ALTER TABLE audit_logs DROP CONSTRAINT IF EXISTS audit_logs_actor_type_check;
ALTER TABLE audit_logs ADD CONSTRAINT audit_logs_actor_type_check CHECK (actor_type IN ('anonymous', 'human', 'service_account', 'system'));
CREATE INDEX IF NOT EXISTS idx_audit_logs_actor_service_account_id ON audit_logs (actor_service_account_id);
