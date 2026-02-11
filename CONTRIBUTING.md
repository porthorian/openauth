# Contributing to OpenAuth

## Project Goals
- Deliver secure, transport-agnostic authentication primitives for Go applications.
- Keep integration simple and transparent for adopters.

## Getting Started
1. Fork and clone the repository.
2. Create a branch for your change.
3. Run checks locally before opening a PR.

## Local Checks
- Run tests:
- `go test ./...`
- Keep formatting clean:
- `gofmt -w .`

## Contribution Types
- Bug fixes
- Security hardening
- New adapters and integrations
- Documentation and examples
- Test coverage improvements

## Pull Request Guidelines
- Keep PRs scoped and focused.
- Include rationale and expected behavior changes.
- Add or update tests for code changes.
- Update docs when behavior, APIs, or support commitments change.
- If auth contracts change, update all affected docs and examples in the same PR (`AGENTS.md`, `ROADMAP.md`, `COMPATIBILITY.md`, and example READMEs/code).
- Add migration notes when a change could affect existing users.

## Design and Planning Alignment
- Major changes should align with `AGENTS.md` roadmap and architecture.
- If scope changes, update `ROADMAP.md` and relevant policy documents.
- Any structural change (package layout, commands, interfaces, contracts, migrations) must include a matching `AGENTS.md` update.

## Security and Credential Rules
- Do not add plaintext password storage.
- Do not add username storage in OpenAuth-managed persistence.
- Password verifier material is allowed when required by design.
- Do not log raw credentials or tokens.

## Commit and Release Hygiene
- Use clear commit messages.
- Keep release-facing changes reflected in changelog and compatibility notes.

## Code of Conduct
- Be respectful and constructive in issues, reviews, and discussions.
