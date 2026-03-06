BEGIN;

CREATE SCHEMA IF NOT EXISTS openauth;
CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TYPE openauth.status_enum AS ENUM ('active', 'inactive', 'revoked', 'expired');
CREATE TYPE openauth.material_type_enum AS ENUM ('password', 'access_token', 'refresh_token', 'api_key', 'client_secret');

CREATE TABLE IF NOT EXISTS openauth.auth (
  id UUID NOT NULL PRIMARY KEY DEFAULT gen_random_uuid(),
  status openauth.status_enum NOT NULL,
  date_added TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
  date_modified TIMESTAMPTZ NULL,
  material_type openauth.material_type_enum NOT NULL,
  material_hash TEXT NOT NULL,
  expires_at TIMESTAMPTZ NULL,
  revoked_at TIMESTAMPTZ NULL
);

CREATE TABLE IF NOT EXISTS openauth.auth_metadata (
  id UUID NOT NULL PRIMARY KEY DEFAULT gen_random_uuid(),
  auth_id UUID NOT NULL,
  date_added TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
  key VARCHAR(255) NOT NULL,
  value TEXT NOT NULL,

  CONSTRAINT fk_auth_metadata_auth_id
    FOREIGN KEY (auth_id)
    REFERENCES openauth.auth (id)
    ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS openauth.subject_auth (
  id UUID NOT NULL PRIMARY KEY DEFAULT gen_random_uuid(),
  auth_id UUID NOT NULL UNIQUE,
  subject TEXT NOT NULL,
  date_added TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
  date_modified TIMESTAMPTZ NULL,

  CONSTRAINT fk_subject_auth_auth_id
    FOREIGN KEY (auth_id)
    REFERENCES openauth.auth (id)
    ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_subject_auth_subject ON openauth.subject_auth (subject);
CREATE INDEX IF NOT EXISTS idx_subject_auth_auth_id ON openauth.subject_auth (auth_id);

CREATE TABLE IF NOT EXISTS openauth.auth_log (
  id UUID NOT NULL PRIMARY KEY DEFAULT gen_random_uuid(),
  auth_id UUID NOT NULL,
  subject TEXT NOT NULL,
  event TEXT NOT NULL,
  occurred_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
  date_added TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
  metadata JSONB NULL,

  CONSTRAINT fk_auth_log_auth_id
    FOREIGN KEY (auth_id)
    REFERENCES openauth.auth (id)
    ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_auth_log_auth_id ON openauth.auth_log (auth_id);
CREATE INDEX IF NOT EXISTS idx_auth_log_subject ON openauth.auth_log (subject);

CREATE TABLE IF NOT EXISTS openauth.subject_role (
  subject TEXT NOT NULL,
  tenant TEXT NOT NULL,
  role_key TEXT NOT NULL,
  date_added TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,

  CONSTRAINT pk_subject_role PRIMARY KEY (subject, tenant, role_key)
);

CREATE INDEX IF NOT EXISTS idx_subject_role_subject_tenant ON openauth.subject_role (subject, tenant);

CREATE TABLE IF NOT EXISTS openauth.subject_permission_override (
  subject TEXT NOT NULL,
  tenant TEXT NOT NULL,
  permission_key TEXT NOT NULL,
  effect TEXT NOT NULL CHECK (effect IN ('grant', 'deny')),
  date_added TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,

  CONSTRAINT pk_subject_permission_override PRIMARY KEY (subject, tenant, permission_key)
);

CREATE INDEX IF NOT EXISTS idx_subject_permission_override_subject_tenant
  ON openauth.subject_permission_override (subject, tenant);

COMMIT;
