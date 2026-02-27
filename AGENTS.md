# openauth Planning Document

## Mission
Build a Go authentication library that provides a consistent auth model across application styles and protocols, including REST/HTTP APIs, gRPC services, OAuth/OIDC flows, and SAML-based flows.

## Product Goal
`openauth` should let application teams integrate authentication once and expose it through multiple transports without rewriting core auth logic.

## Public Import Path
- Primary public package is the repository root: `github.com/porthorian/openauth`.
- Supporting packages remain under `pkg/...`.

## Design Principles
- Transport-agnostic core: business auth logic must not depend on HTTP, gRPC, or SAML details.
- Explicit interfaces: every provider and transport integration is behind small, testable interfaces.
- Secure defaults: sane defaults for token lifetimes, key rotation hooks, and cookie/session safety.
- Incremental adoption: teams can adopt one integration (for example HTTP middleware) without adopting everything.
- Code comment policy: remove explanatory "what" comments; keep comments only when they explain "why" a decision exists.
- Root-first API: consumers should import `github.com/porthorian/openauth` for the main integration surface.
- Transparent by default: roadmap, API decisions, and release behavior are documented publicly and consistently.
- Interchangeable source-of-truth adapters: PostgreSQL and SQLite implement the same persistence contracts and are swappable without auth-layer changes.
- Redis is cache-only: never a source of truth for identities, roles, permissions, or auth configuration.
- Policy-driven persistence: auth profiles define source-of-truth ownership, cache behavior, and failure handling through a persistence policy matrix.
- Focused service dependencies: services compose only required storage contracts and avoid a monolithic storage interface.
- Credential ownership boundary: implementing applications own username identity mapping; OpenAuth may persist password hash material (no usernames) plus token/session artifacts and authorization policy data.
- Minimal dependencies: default core should stay lightweight; optional protocol adapters can live in separate packages/modules.

## Transparency and Adoption Strategy
- Publish a public roadmap tied to milestones in this plan.
- Maintain a clear compatibility policy (SemVer behavior, deprecation windows, and upgrade guidance).
- Keep architectural decisions visible via ADRs and changelog entries.
- Ship runnable examples for each auth entrypoint/approach and each supported transport.
- Document security posture clearly: threat model summary, disclosure process, and hardening defaults.
- Keep contributor onboarding simple: contribution guide, issue/PR templates, and release checklist.
- Any structural change must include matching updates to `AGENTS.md` in the same change set.

## Change Governance
- `AGENTS.md` is the source of truth for architecture and scope decisions.
- Any structural change (commands, package layout, contracts, migrations, and architecture boundaries) must update `AGENTS.md` before merge.
- If project structure and `AGENTS.md` diverge, updating `AGENTS.md` is a required blocking task.
- File edit workflow: apply inline patches for updates; do not remove/recreate files when modifying existing files.
- Tooling workflow: do not run git commands.

## Initial Scope (v0)
- User identity model and claims model.
- Session + token validation primitives.
- Authentication entrypoints: password and access-token authentication.
- Token profiles and approaches: JWT, OIDC, DirectJWT, OpaqueIntrospection, and PhantomToken.
- Auth approaches: direct JWT verification, opaque token introspection, and Phantom Token.
- Role and permission model using bitwise masks.
- Storage migration and initial seed support for bootstrapping auth data.
- Unified auth-material persistence model with a subject linkage table (no username storage).
- Interchangeable source-of-truth adapters for PostgreSQL and SQLite.
- Redis cache adapter for performance acceleration only (not persistence).
- HTTP/REST middleware adapter.
- gRPC unary/stream interceptor adapter.
- OAuth/OIDC adapter boundary (token verification/introspection and claim mapping).
- SAML adapter boundary (interface + reference implementation target), with full implementation deferred if needed.
- Common error model and audit hooks.

## Out Of Scope (v0)
- Full identity provider (IdP) management UI.
- User provisioning lifecycle workflows.
- Multi-language SDKs.
- Authorization policy engine beyond basic role/claim checks.

## Proposed High-Level Architecture
1. Token/session package (`session`)
2. Auth approach package (`approach`) for token handling strategies
3. Authorization package (`authz`) for roles/permissions bitmasks
4. Transport adapters (`transport/http`, `transport/grpc`)
5. Protocol adapters (`protocol/oauth`, `protocol/saml`)
6. Persistence adapters (`storage/*`) with shared source-of-truth contracts
7. Cache adapters (`cache/*`) for optional acceleration
8. Observability hooks (`telemetry`)

Public API and domain interfaces depend on abstractions only. Adapters depend on those interfaces.

## Package Planning (Repo Layout)
- `openauth.go` (root package `openauth`): public entry points and shared options; import path `github.com/porthorian/openauth`.
- `pkg/session`: session manager, token verifier, key resolver interfaces.
- `pkg/crypto/password`: password hashing contracts and implementations.
- `pkg/approach`: strategy interfaces for direct JWT, opaque introspection, and Phantom Token flow.
- `pkg/authz`: permission constants, role definitions, and bitwise authorization helpers.
- `pkg/transport/http`: middleware, context extraction, error writer.
- `pkg/transport/grpc`: unary/stream interceptors, metadata extraction.
- `pkg/protocol/oauth`: OAuth2/OIDC contracts, token introspection/validation abstraction, claim mapping.
- `pkg/protocol/saml`: service provider contract + parser/validator abstractions.
- `pkg/storage`: backend-agnostic source-of-truth persistence interfaces and persistence policy matrix contracts.
- `pkg/storage/postgres`: PostgreSQL adapter implementing persistence contracts.
- `pkg/storage/postgres/migrations`: PostgreSQL-specific SQL migration files.
- `pkg/storage/postgres/seeds`: PostgreSQL-specific seed files/routines.
- `pkg/storage/sqlite`: SQLite adapter implementing persistence contracts.
- `pkg/storage/sqlite/migrations`: SQLite-specific SQL migration files.
- `pkg/storage/sqlite/seeds`: SQLite-specific seed files/routines.
- `pkg/storage/testsuite`: shared persistence contract tests executed against each source-of-truth adapter.
- `pkg/cache`: backend-agnostic cache interfaces.
- `pkg/cache/redis`: Redis cache adapter implementing cache contracts only.
- `pkg/cache/memory`: Memory cache adapter implementing cache contracts only.
- `pkg/cache/testsuite`: shared cache contract tests for cache adapters.
- `pkg/storage/migrations`: shared migration conventions and documentation.
- `pkg/storage/seeds`: shared seed conventions and documentation.
- `cmd/openauth`: primary CLI entrypoint with `migrate up [steps]`, `migrate down <steps>`, and `migrate force <version>` subcommands.
- OpenAuth CLI migrations must use a dedicated migration version table in the `openauth` schema (default `openauth.schema_migrations`) to avoid conflicts with other applications using `schema_migrations` in the same database.
- `examples/rest-auth`: runnable REST API authentication example that issues JWTs via `AuthToken`.
- `pkg/errors`: typed errors and translation helpers.

## API Shape (Draft)
- `Authenticator` interface:
  - `AuthPassword(ctx, input) (Principal, error)`
  - `AuthToken(ctx, input) (Principal, error)`
  - `ValidateToken(ctx, token) (Principal, error)`
- `Authenticator` is auth-only; token/session revocation flows are handled outside this interface.
- `Config`:
  - `AuthStore`, `AuthdStore`, `CacheStore`, `Logger`, `Hasher`, `PolicyMatrix`, `DefaultPolicy`
  - `Runtime.Storage.Backend` + backend-specific connection settings (starting with PostgreSQL DSN/driver/pool/ping options)
  - `Runtime.Cache.Backend` + backend-specific cache settings (`memory` and `redis` in v0)
  - `Runtime.KeyStore.Backend` + backend-specific keystore connection settings
- `Client`:
  - `New(auth, config)` initializes configured runtime resources and uses explicit authenticator
  - `NewDefault(config)` initializes configured runtime resources and builds `AuthService` from resolved config
  - `Close() error` closes resources initialized from runtime config
- `PasswordInput`:
  - `UserID`, `Password`, `Metadata`
- `TokenInput`:
  - `UserID`, `Token`, `Metadata`
- `PasswordInput.UserID` is transient input for verifier callbacks and is never persisted by OpenAuth storage adapters.
- `PasswordInput.Password` is never persisted in plaintext; only derived password hash material (hash/salt/params) may be stored.
- `Principal`:
  - `Subject`, `Tenant`, `RoleMask`, `PermissionMask`, `Claims`, `AuthenticatedAt`
- `AuthRecord`:
  - `ID`, `DateAdded`, `DateModified`, `MaterialType`, `MaterialHash`, `TokenFormat`, `TokenUse`, `ExpiresAt`, `RevokedAt`, `Metadata`
- `AuthRecord.ExpiresAt`:
  - `nil` means the auth material does not expire
- `AuthMaterialType` (v0):
  - `password`, `access_token`, `refresh_token`, `api_key`, `client_secret`
- `TokenFormat` (v0):
  - `opaque`, `jwt`
- `TokenUse` (v0):
  - `access`, `refresh`, `id`
- `AuthProfile` (v0):
  - `password_basic`, `refresh_rotating`, `access_opaque_local`, `access_opaque_remote`, `access_jwt`, `api_key`, `client_secret`
- `Authority` (v0):
  - `source_of_truth`, `external_authority`, `self_contained`
- `CacheRole` (v0):
  - `none`, `read_through`, `introspection`
- `FailureMode` (v0):
  - `fail_closed`, `fail_open`
- `PersistencePolicy`:
  - `MaterialType`, `TokenFormat`, `TokenUse`, `Authority`, `CacheRole`, `PersistInSourceOfTruth`, `AllowNonExpiring`, `MaxCacheTTL`, `FailureMode`
- `PersistencePolicyMatrix`:
  - `Policy(profile) (PersistencePolicy, bool)`
- `Storage` contracts (source of truth):
  - `AuthStore`, `SubjectAuthStore`, `SessionStore`, `RoleStore`, `PermissionStore`, `AuthLogStore`
  - implemented by `Postgres` and `SQLite` adapters
- `Password` contracts:
  - `Hasher`
  - default implementation currently uses PBKDF2-SHA256 encoded hashes
- `Storage` dependency bundles:
  - `AuthMaterial`, `AuthdMaterial`
  - no monolithic `Store` interface
- `Cache` contracts (non-authoritative):
  - `TokenCache`, `PrincipalCache`, `PermissionCache`
  - implemented by `Redis` and `Memory` adapters
- Transport adapters call the same `Authenticator` core interface.

## Authentication Approaches (v0)
- Direct JWT: application validates client-presented JWT locally with configured key resolver/JWKS.
- Opaque Introspection: application sends opaque access token to configured introspection endpoint and maps response to `Principal`.
- Phantom Token: edge/gateway accepts external token, validates/introspects it, then forwards a short-lived internal JWT ("phantom") to services; services validate phantom token locally.
- The same access-token auth entrypoint can run on different approaches based on service configuration.

## Storage, Migration, and Seeding (v0)
- Define backend-agnostic persistence contracts and require interchangeability across PostgreSQL and SQLite.
- Define separate cache contracts and keep cache as non-authoritative cache only.
- Keep a capability matrix so behavior is consistent where possible and explicitly documented where backend constraints differ.
- Provide a migration runner abstraction so applications can run schema changes programmatically or via CLI.
- v0 CLI migration runner uses `golang-migrate` for `cmd/openauth migrate up [steps]`, `cmd/openauth migrate down <steps>`, and `cmd/openauth migrate force <version>`, with file-based migration sources under adapter-specific directories.
- v0 CLI rollback treats migration-tracking truncate errors as successful when a down migration intentionally drops the schema containing the migration table.
- Use ordered, versioned migrations for forward schema evolution with deterministic execution.
- Provide idempotent seed routines that can be re-run safely across environments.
- Initial seed dataset includes core permissions, default roles, and baseline auth configuration records only.
- Library-managed schema stores password/token key material in a unified auth table and uses a subject-auth link table, while excluding username columns/fields.
- Auth usage tracking is stored in `auth_log` records, not in auth material rows.
- Persistence behavior is policy-driven by auth profile, including cache role, authority boundary, and fail-open/fail-closed strategy.
- SQL migrations and seeds apply to PostgreSQL and SQLite source-of-truth adapters only.
- SQL artifacts are adapter-specific and live under `pkg/storage/postgres/...` and `pkg/storage/sqlite/...`.
- PostgreSQL migration baseline currently starts at `pkg/storage/postgres/migrations/0001_init.up.sql` and `pkg/storage/postgres/migrations/0001_init.down.sql`, creates schema `openauth`, and creates `openauth.auth` used by the active Postgres adapter queries.
- Redis cache uses TTL and namespace versioning; it never receives authoritative seed data.
- Support startup policy options: migration-only, seed-only, or migrate-then-seed.

## Authorization Model (Bitwise RBAC)
- `PermissionMask` uses `uint64` where each permission is one bit flag.
- `RoleMask` uses `uint64`; each role maps to a pre-defined permission mask.
- Effective permissions are computed by bitwise OR across assigned roles and direct grants.
- Authorization checks use bitwise AND and compare against required permissions.
- Default policy is deny when required permission bits are not fully present.
- Example semantics:
  - Grant: `effective |= PermissionRead`
  - Check any: `(effective & (PermissionRead | PermissionWrite)) != 0`
  - Check all: `(effective & required) == required`

## Auth Method Semantics (v0)
- Basic: validates user-supplied identity key + password through a pluggable verifier callback; OpenAuth may persist password hash material only (no username storage, no plaintext passwords).
- Bearer: extracts bearer value from transport metadata and delegates to configured token validator.
- JWT: verifies signature and registered claims (`iss`, `aud`, `exp`, `nbf`, `iat`) with configurable key resolver.
- OIDC: validates ID token semantics on top of JWT checks, including issuer, audience/client ID, nonce (where applicable), and claim normalization.

## Security Baseline
- Support pluggable signing key lookup and key rotation.
- Support clock skew tolerance configuration.
- Enforce strict issuer/audience validation in token validators.
- Enforce TLS requirement guidance for Basic credentials and never log raw credentials/tokens.
- For Phantom Token, enforce short TTL, scoped audience, and clear trust boundary between edge and service.
- Enforce deny-by-default authorization checks for role/permission evaluation.
- Never persist usernames in OpenAuth-managed stores.
- Never persist plaintext passwords; only strong password hash material (hash/salt/params) is allowed at rest.
- Never authorize from cache entries without source-of-truth validation guarantees for the configured flow.
- Ensure seed data never inserts default plaintext credentials or reusable weak secrets.
- Provide secure cookie/session defaults for HTTP.
- Provide redaction-safe error messages and structured audit events.

## Milestone Plan
1. Foundation
2. Core Auth Engine
3. HTTP Adapter
4. gRPC Adapter
5. OAuth Adapter
6. SAML Adapter
7. Hardening + Docs

### Milestone 1: Foundation
- Finalize package layout.
- Define foundational interfaces and error taxonomy.
- Define persistence contracts and source-of-truth adapter compatibility requirements.
- Define cache contracts and cache invalidation/versioning requirements.
- Define and document credential ownership boundary (application-managed username identity mapping, OpenAuth-managed hashed auth material + subject/session artifacts).
- Select migration mechanism and define migration file conventions.
- Define seed framework conventions and idempotency requirements.
- Add CI checks (test, lint, vet).
- Add architecture decision record (ADR) template.

### Milestone 2: Core Auth Engine
- Implement `Principal`, claims handling, context helpers.
- Implement token/session validation interface and reference in-memory impl.
- Implement password and access-token auth entrypoints.
- Implement auth approach dispatcher for Direct JWT, Opaque Introspection, and Phantom Token.
- Implement bitwise role/permission model and authorization evaluation helpers.
- Implement initial storage schema migration set and seed pipeline.
- Implement unified auth-material persistence adapters with subject linkage (no username storage tables).
- Implement PostgreSQL and SQLite adapters against shared persistence contracts.
- Implement Redis adapter against cache contracts only.
- Implement persistence contract tests and cache contract tests.
- Add unit tests for validation behavior and edge cases.

### Milestone 3: HTTP Adapter
- Implement middleware for auth extraction/validation.
- Support bearer token and secure cookie strategies.
- Add examples for `net/http` and common router usage.

### Milestone 4: gRPC Adapter
- Implement unary and stream interceptors.
- Map auth failures to canonical gRPC status codes.
- Add end-to-end tests with test gRPC service.

### Milestone 5: OAuth Adapter
- Define OAuth2/OIDC adapter contracts.
- Implement token validation/introspection flow with provider-agnostic interfaces.
- Add OIDC discovery and JWKS resolver abstractions.
- Add Phantom Token integration guidance and internal-token validation profile.
- Add claim normalization and mapping tests.

### Milestone 6: SAML Adapter
- Define SAML adapter contracts.
- Implement request/response validation path with selected SAML library.
- Add conformance tests for assertion parsing and claim mapping.

### Milestone 7: Hardening + Docs
- Threat-model review and security checklist.
- Benchmark critical paths.
- Write migration/integration guides and full examples.
- Publish compatibility/deprecation policy and release playbook.
- Publish contributor and security disclosure documentation.

## Quality Gates
- Unit test coverage for foundational packages >= 95%.
- Adapter behavior tests for HTTP and gRPC.
- Approach tests for direct JWT, opaque introspection, and Phantom Token flows.
- Authorization tests for role expansion and bitmask checks (`any` and `all` semantics).
- Migration tests validating ordered application and repeatable execution behavior.
- Seed tests validating idempotency and expected baseline records.
- Persistence contract tests must pass for PostgreSQL and SQLite adapters.
- Schema/persistence checks must confirm no username storage and no plaintext password storage in library-managed adapters.
- Cache contract tests must pass for Redis and Memory adapters, including TTL and invalidation behavior where applicable.
- Public examples for all supported auth entrypoints/approaches must compile in CI.
- Every release must include changelog entries and migration notes for breaking/behavioral changes.
- Fuzz tests for token parsing/claim decoding.
- Security checks in CI (dependency scanning + `govulncheck`).

## Key Open Decisions
- Token strategy for v0: JWT only, opaque sessions, or both.
- Auth material persistence format for source-of-truth storage: raw key vs hashed key + metadata (recommended: hashed key + metadata).
- Basic credential representation in unified auth table: material-type specific metadata shape + hash algorithm parameters (recommended: Argon2id).
- Approach support in v0: include all three approaches by default or ship Phantom Token as optional adapter.
- Phantom token issuer responsibility: API gateway only vs gateway plus sidecar patterns.
- Permission mask size for v0: `uint32` vs `uint64` (default `uint64`).
- Source of role definitions: static compile-time constants vs configurable role registry.
- Storage abstraction depth: minimal session/user interfaces vs richer repository pattern.
- Migration tooling choice: `golang-migrate` for v0 CLI and migration conventions.
- Source-of-truth capability parity policy across PostgreSQL and SQLite for transactions, indexing, and constraints.
- Cache role policy details: TTL defaults, key namespacing, invalidation triggers, and fail-open vs fail-closed behavior.
- Seed ownership model: library-managed baseline only vs consumer-extendable seed hooks.
- OAuth/OIDC support level in v0: verify-only, introspection, or full auth code flow helpers.
- Basic authentication source for v0: callback-driven validation with optional OpenAuth-managed password-hash storage (without usernames).
- API stability target for public interfaces: pre-v1 fast iteration vs stricter compatibility guarantees.
- Release transparency policy: cadence, changelog format, and support window commitments.
- SAML library selection and maintenance policy.
- Module strategy: single module vs split optional adapters into submodules.

## Immediate Next Steps
1. Confirm v0 auth strategy: JWT, session, or hybrid.
2. Confirm v0 auth approach strategy: Direct JWT, Opaque Introspection, Phantom Token (all or subset).
3. Define Phantom Token trust model (issuer, signing keys, audience, TTL).
4. Define backend-agnostic source-of-truth persistence contracts (`AuthStore`, `SubjectAuthStore`, `SessionStore`, `RoleStore`, `PermissionStore`, `AuthLogStore`) and focused dependency bundles.
5. Define source-of-truth capability matrix for PostgreSQL and SQLite.
6. Define cache contracts and cache-role invalidation/TTL strategy.
7. Document and harden `golang-migrate` conventions for SQL source-of-truth adapters.
8. Define auth-material persistence strategy (raw key vs hashed key + metadata).
9. Define Basic auth persistence strategy in unified auth records (credential key model without username + hash/salt/params).
10. Define initial schema objects and first migration set (auth + subject_auth + auth_log + session + authz policy, without username columns).
11. Define baseline seed dataset (permissions, roles, auth config defaults only).
12. Define v0 permission catalog and assign bit flags.
13. Define v0 roles and their permission masks.
14. Define transparency artifacts: roadmap board, changelog format, compatibility policy, and release checklist.
15. Confirm OAuth/OIDC scope for v0 (provider-agnostic validation only vs login flow helpers).
16. Confirm target Go version and dependency constraints.
17. Create initial package skeleton and interface stubs under `pkg/...`.
18. Define/stabilize the root package API in `openauth.go` that composes `pkg/...` components.
19. Add test harness and CI baseline.
