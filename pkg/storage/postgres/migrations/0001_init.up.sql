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

CREATE TABLE IF NOT EXISTS openauth.auth_event (
  id UUID NOT NULL PRIMARY KEY DEFAULT gen_random_uuid(),
  auth_id UUID NOT NULL,
  date_added TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  user_agent TEXT NOT NULL,
  ip_address INET NOT NULL,
  login_status BOOLEAN NOT NULL,
  error_message TEXT NULL,
  
  CONSTRAINT fk_auth_event_auth_id
      FOREIGN KEY (auth_id)
      REFERENCES openauth.auth (id)
      ON DELETE CASCADE
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

CREATE TABLE IF NOT EXISTS openauth.auth_user (
  id UUID NOT NULL PRIMARY KEY DEFAULT gen_random_uuid(),
  auth_id UUID NOT NULL UNIQUE,
  user_id UUID NOT NULL,
  date_added TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,

  CONSTRAINT fk_auth_user_user_id
    FOREIGN KEY (user_id)
    REFERENCES openauth.auth (id)
    ON DELETE CASCADE,

  CONSTRAINT fk_auth_user_auth_id
    FOREIGN KEY (auth_id)
    REFERENCES openauth.auth (id)
    ON DELETE CASCADE
);

COMMIT;
