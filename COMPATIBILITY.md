# Compatibility Policy

## Scope
This policy defines compatibility expectations for OpenAuth APIs, behaviors, and supported platforms.

## Versioning
- OpenAuth uses Semantic Versioning (`MAJOR.MINOR.PATCH`).
- Until `v1.0.0`, breaking changes may occur in `MINOR` releases.
- `PATCH` releases must not include intentional breaking API changes.

## Public API Surface
- Stable entry point: `github.com/porthorian/openauth` (root package).
- Packages under `pkg/...` are public but may evolve faster before `v1.0.0`.
- Breaking changes must be documented in release notes with migration guidance.

## Current Authenticator Contract
- Root auth interfaces currently use:
- `Authorize(ctx, AuthInput)`
- `CreateAuth(ctx, CreateAuthInput)`
- `ValidateToken(ctx, token)`
- Input contracts are currently:
- `AuthInput{UserID, Type, Value, Metadata}`
- `InputType` values: `password`, `token`
- `CreateAuthInput{UserID, Value, ExpiresAt, Metadata}`
- Any rename/removal/signature change to these is a breaking API change.

## Deprecation
- Deprecations should be announced before removal when feasible.
- Target deprecation window: at least one minor release before removal.
- Urgent security changes may shorten this window.

## Runtime and Tooling Support
- Go versions: support the version declared in `go.mod` and the previous major Go release when feasible.
- Datastores:
- Source of truth: PostgreSQL and SQLite.
- Cache only: Redis (and in-memory cache for local/dev).

## Behavioral Compatibility
- Security fixes may tighten validation behavior.
- Tightening defaults is allowed if it closes a vulnerability or removes unsafe behavior.
- Such changes must be called out as behavioral changes in release notes.

## Authentication and Credential Storage Guarantees
- OpenAuth does not persist usernames in library-managed stores.
- OpenAuth does not persist plaintext passwords.
- Password verifier material (hash/salt/parameters) may be persisted.

## Migration Notes Requirement
- Any release with breaking or behavior-impacting changes must include:
- A concise migration section.
- Before/after examples when API changes occur.
- Explicit action items for adopters.
