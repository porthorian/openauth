BEGIN;

CREATE SCHEMA IF NOT EXISTS openauth;

CREATE TABLE IF NOT EXISTS openauth.auth (
  id TEXT PRIMARY KEY,
  status TEXT NOT NULL CHECK (status IN ('active', 'inactive', 'revoked', 'expired')),
  date_added TIMESTAMPTZ NOT NULL,
  date_modified TIMESTAMPTZ NULL,
  material_type TEXT NOT NULL CHECK (
    material_type IN ('password', 'access_token', 'refresh_token', 'api_key', 'client_secret')
  ),
  material_hash TEXT NOT NULL,
  expires_at TIMESTAMPTZ NULL,
  revoked_at TIMESTAMPTZ NULL,
  metadata JSONB NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(metadata) = 'object')
);

CREATE INDEX IF NOT EXISTS idx_auth_status ON openauth.auth (status);
CREATE INDEX IF NOT EXISTS idx_auth_material_type ON openauth.auth (material_type);
CREATE INDEX IF NOT EXISTS idx_auth_expires_at ON openauth.auth (expires_at) WHERE expires_at IS NOT NULL;

COMMIT;
