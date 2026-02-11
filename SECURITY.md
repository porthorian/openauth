# Security Policy

## Scope
This policy covers security vulnerabilities in OpenAuth source code, release artifacts, and default security behavior.

## Reporting a Vulnerability
- Please report vulnerabilities privately through GitHub Security Advisories for this repository.
- Do not open public issues for unpatched vulnerabilities.
- Include reproduction details, impact, affected versions, and suggested mitigations when possible.

## Response Expectations
- Initial acknowledgement target: within 3 business days.
- Triage target: within 7 business days.
- Remediation timeline depends on severity and exploitability.

## Disclosure Process
- We prefer coordinated disclosure.
- A fix will be prepared and released before full public disclosure when practical.
- Release notes will clearly identify security-impacting changes.

## Security Guarantees and Boundaries
- OpenAuth does not persist usernames in library-managed stores.
- OpenAuth never stores plaintext passwords.
- Password storage is limited to verifier material (hash/salt/parameters).
- Redis is cache-only and never a source of truth.
- `UserID` may be accepted at runtime for auth input, but that identifier must not be persisted as a username field by library-managed adapters.
- Raw password and access-token input values should be treated as secrets and never logged.

## Recommended Defaults
- Use strong password hashing (Argon2id recommended).
- Use short-lived tokens and strict issuer/audience checks.
- Enforce TLS in all environments handling credentials or tokens.
- Rotate keys regularly and support revocation flows.

## Supported Versions
- Security fixes are prioritized for the latest release line.
- Older lines may receive fixes at maintainer discretion.
