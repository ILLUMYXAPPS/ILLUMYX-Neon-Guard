# ILLUMYX Neon Guard 🔒⚡

ILLUMYX Neon Guard is an application access-control foundation for ILLUMYX software.

## Purpose

Neon Guard evaluates an access request and returns a deterministic security decision:

- `ALLOW`
- `DENY`

The first implementation is intentionally framework-independent TypeScript so it can be integrated into the eventual Android, iOS, web, or backend application without coupling the security policy to a UI framework.

## Access-control model

```text
Access Request
      ↓
   AccessGate
      ↓
   AccessPolicy
      ↓
IdentityHasher + BlockedIdentityStore
      ↓
 ALLOW / DENY
```

### Security principles

1. Store normalized identity values as SHA-256 hashes rather than plaintext.
2. Keep authorization decisions inside the ILLUMYX-controlled application/service boundary.
3. Do not expose the protected identifier or internal blocklist to an unauthorized user.
4. Fail closed when a security decision cannot safely be made.
5. Keep security logging free of plaintext phone numbers and other unnecessary sensitive data.

## Project structure

```text
access-control/
├── AccessGate.ts
├── AccessPolicy.ts
├── IdentityHasher.ts
└── BlockedIdentityStore.ts

security/
├── SecurityEvent.ts
└── SecurityLogger.ts

tests/
└── access-control/
    └── AccessGate.test.ts
```

## Scope

Neon Guard can enforce authorization within applications and services controlled by ILLUMYX. It cannot independently disable unrelated accounts, telecommunications numbers, third-party services, or devices.

## Development status

- [x] Access-control architecture
- [x] TypeScript security core
- [x] SHA-256 identity hashing
- [x] In-memory blocked identity store
- [x] Deterministic allow/deny gate
- [x] Security event model
- [x] Unit-test coverage for core decisions
- [ ] Persistent production blocklist
- [ ] Application-specific authentication integration
- [ ] Android/iOS integration
- [ ] Production security review

## License

Copyright © ILLUMYX. All rights reserved unless a specific file or third-party dependency states otherwise.
