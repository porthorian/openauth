# `pkg/approach`

`pkg/approach` defines token-validation strategies behind a common interface:

- `direct_jwt`
- `opaque_introspection`
- `phantom_token`

Each approach implements:

- `Name() string`
- `Validate(ctx, token) (Result, error)`

## When To Use Each Approach

### Direct JWT
- Use when services can verify JWTs locally with configured signing keys/JWKS.
- Use when low latency and reduced external dependency per request are priorities.
- Best when you can operate reliable key rotation and claim-validation policies in each service.

### Opaque Introspection
- Use when tokens must be checked against an external authority on each validation.
- Use when revocation and policy changes need immediate central enforcement.
- Best when network dependency to introspection authority is acceptable.

### Phantom Token
- Use when an edge/gateway validates external tokens and exchanges them for short-lived internal JWTs.
- Use when downstream services should not directly trust or parse external identity-provider tokens.
- Best in microservice environments with a clear gateway trust boundary and strict internal token TTL/audience controls.

## Notes
- You can register multiple handlers in one `Registry` and select by approach name.
- All handlers return a normalized `Result` (`Subject`, `Tenant`, `Claims`, `ExpiresAt`) so upstream auth flow stays transport-agnostic.
