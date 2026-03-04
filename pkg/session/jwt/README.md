# `pkg/session/jwt`

JWT implementation for OpenAuth session and token interfaces.

## What It Implements
- `session.TokenIssuer`
- `session.TokenValidator`
- `session.SessionManager`

## Behavior Summary
- Issues signed JWTs with required registered claims: `sub`, `exp`, `iat`, `nbf`.
- Validates JWT signature and registered claims (`iss`, `aud`, `exp`, `nbf`, `iat`) using configurable clock skew.
- Supports `kid` header + `session.KeyResolver` for key lookup/rotation.
- Issues session tokens with:
  - `openauth_session: true` (configurable claim key)
  - `jti` session identifier
- Tracks revoked session IDs (`jti`) in process memory.

## Supported Algorithms (Current)
- `HS256`
- `HS384`
- `HS512`

## Quick Start
```go
manager, err := jwt.NewManager(jwt.Config{
    SigningKey: session.Key{
        ID:        "v1",
        Algorithm: "HS256",
        Material:  []byte("replace-with-strong-secret"),
    },
    Issuer:    "openauth.example",
    Audience:  []string{"api"},
    ClockSkew: 30 * time.Second,
})
if err != nil {
    return err
}

token, err := manager.IssueToken(ctx, "subject-123", session.Claims{
    "role": "admin",
}, 15*time.Minute)
if err != nil {
    return err
}

claims, err := manager.ValidateToken(ctx, token)
if err != nil {
    return err
}

sessionToken, err := manager.IssueSession(ctx, "subject-123", 24*time.Hour)
if err != nil {
    return err
}

ok, err := manager.ValidateSession(ctx, sessionToken)
if err != nil {
    return err
}
_ = claims
_ = ok
```

## Notes
- Revocation is in-memory only and does not survive process restarts.
- Reserved registered claims are owned by the manager during issuance and cannot be overridden by caller-provided claims.
