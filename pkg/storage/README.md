# Storage Policy Matrix

`pkg/storage/policy.go` defines a backend-agnostic persistence policy matrix.

## Why

The same auth material type can have different authority and cache behavior depending on profile (for example local opaque access tokens vs externally introspected access tokens). The policy matrix keeps this explicit and testable.

## Core Types

- `AuthProfile`
- `Authority`
- `CacheRole`
- `FailureMode`
- `PersistencePolicy`
- `PersistencePolicyMatrix`

## Default Profiles

- `password_basic`
- `refresh_rotating`
- `access_opaque_local`
- `access_opaque_remote`
- `access_jwt`
- `api_key`
- `client_secret`

## Non-Expiring Material

`AuthRecord.ExpiresAt == nil` means non-expiring material and should only be allowed when `PersistencePolicy.AllowNonExpiring` is true.
