# Adversarial security test matrix

The trusted-device security layer must reject or safely handle:

- More than three active trusted devices
- Revoked devices attempting access
- Replayed provider event IDs
- Unauthorized device registration, revocation, and replacement
- Missing device metadata
- Unknown device identifiers
- Raw token persistence or logging
- Duplicate audit and alert delivery

Production integration tests must additionally cover transaction races, database uniqueness/locking, provider event retries, provider metadata gaps, and alert-channel failures.

A green unit suite is necessary but is not sufficient evidence for production readiness; provider and database integration tests remain required.
