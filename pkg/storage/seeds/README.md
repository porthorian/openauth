# Seeds

This directory contains shared seed conventions and documentation.

## Scope
- PostgreSQL seed SQL/routines live in `pkg/storage/postgres/seeds`.
- SQLite seed SQL/routines live in `pkg/storage/sqlite/seeds`.
- Seed data should include permissions, roles, and auth configuration defaults only.
- Seed data must not include username data.
- Seed data must not include plaintext passwords or reusable weak secrets.

## Behavior
- Seed routines should be safe to run repeatedly.
