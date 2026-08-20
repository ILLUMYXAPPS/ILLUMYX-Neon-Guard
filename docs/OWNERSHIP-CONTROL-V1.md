# Neon Guard Ownership Control v1

## Purpose

Neon Guard must protect ownership and control metadata from unauthorized modification or transfer.

## Owner authority

The canonical owner is **Aaron Stephen Paszek**.

The owner name is descriptive metadata only. Authorization must never rely on matching a display name.

## Required controls

1. Ownership changes require authenticated owner authorization.
2. Authorization must use a cryptographic credential or passkey controlled by the owner.
3. Ordinary administrators must not be able to unilaterally transfer ownership.
4. Ownership changes must be authenticated server-side.
5. Every ownership-change attempt must produce a security event.
6. Failed or unauthorized attempts must be rejected and alerted.
7. Ownership transfer must invalidate affected sessions and credentials where appropriate.
8. Recovery mechanisms must not silently bypass ownership authorization.
9. Ownership changes must be auditable.
10. The mobile client must never be the sole authority for an ownership decision.

## Presence requirement

Software cannot reliably prove that a person is physically present. Neon Guard therefore interprets the requirement as: an ownership change requires a valid owner-controlled cryptographic approval from an authenticated trusted device or passkey.

## Security boundary

The server is authoritative for ownership state and authorization. The mobile application may request an ownership operation but cannot grant itself ownership or override the server decision.

## Release gate

Ownership-control implementation must pass automated tests, CI, security review, and independent approval before being merged into `main`.
