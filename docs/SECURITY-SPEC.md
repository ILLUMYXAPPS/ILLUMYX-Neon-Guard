# Neon Guard Security Specification

## Purpose

Neon Guard is a mobile privacy and security product intended to help users detect, prevent, limit, and respond to unauthorized access and common digital security threats.

Neon Guard does not promise that a device or account is impossible to compromise. Security decisions must be based on explicit controls, observable events, and conservative failure behaviour.

## Security principles

1. **Server-authoritative policy**: authorization policy, sensitive blocklists, and signing secrets remain server-side.
2. **Fail closed**: if a security decision cannot be validated, access is not granted by default.
3. **Least privilege**: mobile clients receive only the data and permissions needed for their function.
4. **Explicit trust**: trusted devices and sessions are registered and revocable.
5. **Auditability**: security-relevant decisions generate privacy-conscious audit events.
6. **Privacy by design**: collect the minimum information needed, protect it in transit and at rest, and provide appropriate deletion/revocation controls.
7. **No covert surveillance**: Neon Guard operates only on devices, accounts, and resources the user is authorized to protect.

## Threat model

### Threats in scope

- Stolen or leaked credentials
- Unknown-device sign-ins
- Session/token theft
- Replayed or malformed authorization requests
- Automated API abuse and rate-limit exhaustion
- Compromised client state attempting to bypass local checks
- Accidental exposure of security logs or sensitive identifiers

### Out of scope for a single client release

- Guaranteed protection against every zero-day exploit
- Physical forensic recovery from a fully compromised device
- Security of third-party services outside Neon Guard's control

## Required controls

### Authentication and sessions

- Use modern platform-supported authentication and short-lived sessions where practical.
- Support explicit session revocation.
- Never embed long-lived server secrets in the mobile application.

### Trusted devices

- Register devices through authenticated enrollment.
- Give each device a revocable server-side identity.
- Treat a new device as untrusted until enrollment succeeds.

### Authorization

- Authorization decisions are made by the trusted backend.
- The client must not contain the authoritative allow/deny policy.
- Non-success backend responses are treated as failures.

### Transport

- Production endpoints must use HTTPS/TLS.
- Certificate and authentication hardening must be reviewed before production release.

### Abuse controls

- Apply server-side rate limits.
- Detect repeated failed authentication and suspicious request patterns.
- Avoid exposing sensitive information through error messages.

### Logging and alerts

- Record security-relevant events with data minimisation.
- Alert users for meaningful events such as a new device or suspicious authentication.
- Never place passwords, API secrets, or raw authentication tokens in logs.

## Mobile security requirements

- Store sensitive user/session material only in appropriate platform-secure storage.
- Avoid hard-coded credentials and secrets.
- Validate server responses before taking security-sensitive actions.
- Keep security policy updates server-controlled where possible.
- Treat a compromised client as untrusted and require backend authorization.

## Privacy requirements

- Document categories of personal data collected.
- Define retention periods before production launch.
- Provide appropriate account/data deletion mechanisms.
- Restrict access to security telemetry.
- Complete jurisdiction-specific privacy and consumer-law review for each launch market.

## Release gates

A production release requires:

- Passing automated tests and security checks
- Independent human code/security review
- Verified production authentication and transport configuration
- No secrets committed to source control
- Documented privacy/data handling
- Dependency and vulnerability review
- Platform-store compliance review
- Rollback and incident-response procedures

## Current implementation status

The iOS client establishes the server-authorized integration boundary. The production backend, authentication hardening, and final security review remain release prerequisites.
