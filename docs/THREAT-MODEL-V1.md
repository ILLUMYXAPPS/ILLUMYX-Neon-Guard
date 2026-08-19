# Neon Guard Threat Model v1

## Assets

- Owner authorization keys
- Trusted-device credentials/tokens
- Authentication sessions
- Ownership state
- Security audit events
- User privacy data

## Primary threats

1. Forged ownership-change requests
2. Replay of previously valid authorization messages
3. Theft or replay of trusted-device credentials
4. Unauthorized recovery or device replacement
5. Privilege escalation by an administrator
6. Client-side authorization bypass
7. Credential leakage through logs or source control
8. Abuse of authentication endpoints

## Security requirements

- Ownership state is authoritative on the server.
- Owner authorization is cryptographically verified against a trusted registry.
- Signed operations are bound to current state/version and must include replay protection in the production protocol.
- Trusted-device credentials are opaque server-issued credentials and are revocable.
- Recovery requires an explicit, auditable authorization flow and cannot silently bypass ownership controls.
- Security logs must not contain plaintext secrets or unnecessary sensitive identifiers.
- Security failures default to deny.

## Explicit non-goals

Neon Guard cannot control unrelated third-party accounts, devices, networks, websites, or telecommunications systems merely because the application exists.

## Assurance gate

Threat-model changes must be reviewed alongside implementation changes that affect ownership, authentication, trusted devices, recovery, or authorization.
