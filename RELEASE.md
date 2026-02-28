# Release Playbook

## Goals
- Make releases predictable.
- Make changes understandable.
- Keep upgrades low-risk.

## Release Cadence
- Target: regular minor releases, patch releases as needed.
- Security or critical bug fixes can ship out-of-band.

## Versioning Rules
- `PATCH`: bug fixes and low-risk changes, no intentional API breaks.
- `MINOR`: new capabilities; pre-`v1.0.0` may include breaking changes with migration notes.
- `MAJOR`: breaking changes after `v1.0.0`.

## Pre-Release Checklist
- Confirm roadmap and milestone status.
- Ensure tests pass (`go test ./...`).
- Ensure examples compile and run.
- Confirm public auth contract docs match code (`Authorize`, `CreateAuth`, `ValidateToken`, `AuthInput`, `InputType`, `CreateAuthInput`).
- Update `CHANGELOG` with categorized entries:
- Added
- Changed
- Fixed
- Security
- Add migration notes for breaking or behavior-impacting changes.
- Confirm docs updates (`ROADMAP.md`, `COMPATIBILITY.md`, and affected guides).

## Build and Version Injection
- CLI build version is injected at compile time through:
- `-ldflags "-X github.com/porthorian/openauth/cmd.BuildVersion=<version>"`
- Example:
- `go build -ldflags "-X github.com/porthorian/openauth/cmd.BuildVersion=v0.1.0" ./cmd/openauth`

## Release Steps
1. Create release branch or prepare release commit.
2. Finalize changelog and migration notes.
3. Tag release (`vX.Y.Z`).
4. Publish release notes with upgrade guidance.
5. Verify published artifacts and tagged source.

## Post-Release
- Monitor issues and regressions.
- Patch quickly if release blockers are reported.
- Update roadmap status for shipped items.
