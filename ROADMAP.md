# openauth Roadmap

## Purpose
This roadmap describes planned delivery for OpenAuth and keeps implementation priorities visible to users and contributors.

## Principles
- Prefer secure defaults over optional hardening.
- Keep adoption friction low with clear docs and runnable examples.
- Keep behavior transparent through changelogs, ADRs, and migration notes.

## Current Status
- Phase: Planning and scaffolding.
- Focus: defining stable interfaces and package boundaries around the current auth contract (`Authorize`, `CreateAuth`, `ValidateToken`).

## Milestones
1. Foundation
- Finalize package layout and interface taxonomy.
- Define persistence and cache contracts.
- Establish migration and seeding conventions.
- Set transparency artifacts (roadmap, compatibility, release and security docs).

2. Core Auth Engine
- Implement auth entrypoints: `Authorize`, `CreateAuth`, and `ValidateToken`.
- Map auth method profiles (Basic, Bearer, JWT, OIDC) onto those entrypoints.
- Implement approaches: DirectJWT, OpaqueIntrospection, PhantomToken.
- Implement persistence policy matrix by auth profile (authority boundary, cache role, and failure mode).
- Implement bitwise role/permission model.
- Implement PostgreSQL and SQLite source-of-truth adapters.
- Implement Redis and memory cache adapters.

3. HTTP Adapter
- Add HTTP middleware and context helpers.
- Add transport examples.

4. gRPC Adapter
- Add unary and stream interceptors.
- Add status-code mapping and transport examples.

5. OAuth Adapter
- Add OAuth2/OIDC contracts and validation/introspection integrations.
- Add discovery and JWKS abstractions.

6. SAML Adapter
- Add SAML contracts and assertion validation flow.
- Add claim mapping tests.

7. Hardening and Documentation
- Complete threat model and hardening checklist.
- Publish migration guides and complete examples.
- Maintain compatibility policy and release playbook.

## Adoption Targets
- Public examples for all supported entrypoints/approaches compile in CI.
- Every release ships with changelog and migration notes.
- Contributor onboarding remains under 15 minutes for first local run.

## Change Management
- Roadmap updates should be included in PRs that materially change scope, sequencing, or support commitments.
