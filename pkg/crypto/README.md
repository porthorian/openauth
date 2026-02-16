# Password Hashing

This package contains password hash contracts and implementations used by auth services.

Current default implementation:

- PBKDF2-SHA256 with encoded hash format:
  - `pbkdf2$sha256$<iterations>$<salt_b64>$<derived_b64>`
