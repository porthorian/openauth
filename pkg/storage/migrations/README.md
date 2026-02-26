# Migrations

This directory contains shared migration conventions and documentation.

## Scope
- PostgreSQL SQL migrations live in `pkg/storage/postgres/migrations`.
- SQLite SQL migrations live in `pkg/storage/sqlite/migrations`.
- Schemas include `auth`, `subject_auth`, `auth_log`, `session`, and authz policy tables.
- `auth.expires_at` must allow `NULL` to represent non-expiring auth material.
- Migration schemas must exclude username columns and plaintext password storage.

## Naming
- Use ordered, forward-only files.
- `golang-migrate` naming requires directional files per version.
- Example: `0001_init.up.sql`, `0001_init.down.sql`, `0002_add_auth_indexes.up.sql`, `0002_add_auth_indexes.down.sql`.
