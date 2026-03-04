# JWT Session Open Questions

This file captures decisions that are still open after implementing `pkg/session/jwt`.

## 1. Signing Algorithm Scope
- Current implementation supports HMAC only (`HS256`, `HS384`, `HS512`).
- Open question: should v0 also include asymmetric algorithms (`RS256`, `ES256`, etc.) for multi-service verification without shared symmetric keys?

## 2. Revocation Storage Model
- Current session revocation is process-local in-memory (`jti` map).
- Open question: should revocation become a storage-backed contract for cross-instance consistency and restart durability?

## 3. Audience Matching Policy
- Current validation passes when any configured audience matches any token audience value.
- Open question: do we want stricter semantics for some profiles (for example: require all configured audiences, or exact set match)?

## 4. Session Claim Contract
- Current session marker defaults to `openauth_session` and is configurable.
- Open question: should this claim key be fixed to avoid interoperability drift across services?

## 5. Revocation Result Semantics
- Current `ValidateSession` behavior:
  - invalid token/session shape -> error
  - revoked but otherwise valid -> `ok=false`, `err=nil`
- Open question: should revoked sessions return a dedicated error for easier transport-level mapping?
