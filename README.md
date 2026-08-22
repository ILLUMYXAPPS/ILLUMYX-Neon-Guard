# ILLUMYX Neon Guard 🔒⚡

ILLUMYX Neon Guard is an application access-control foundation for ILLUMYX software.

## Purpose

Neon Guard evaluates an access request and returns a deterministic security decision:

- `ALLOW`
- `DENY`

The implementation is framework-independent TypeScript so it can be integrated into an Android, iOS, web, or backend application without coupling the security policy to a UI framework.

## Access-control model

```text
Authentication request
        ↓
    AccessGate
        ↓
    AccessPolicy
        ↓
IdentityHasher + BlockedIdentityStore
        ↓
    ALLOW / DENY
```

For asynchronous authentication flows, call `AccessGate.evaluateAsync()` before issuing or accepting the authenticated session. A `DENY` result must stop the authentication flow.

### Security principles

1. Store normalized identity values as keyed HMAC-SHA-256 digests rather than plaintext or unsalted hashes.
2. Keep the HMAC secret outside source control and inject it through the application's secret-management mechanism.
3. Keep authorization decisions inside the ILLUMYX-controlled application/service boundary.
4. Do not expose the protected identifier or internal blocklist to an unauthorized user.
5. Fail closed when a security decision cannot safely be made.
6. Keep security logging free of plaintext phone numbers and other unnecessary sensitive data.

## Persistence

`PersistentBlockedIdentityStore` persists only HMAC digests in a local JSON file and writes through a temporary file before an atomic rename. It is a development adapter, not a distributed production database.

`TransactionalStoreAdapter` defines the production integration boundary. A production implementation must supply real BEGIN/COMMIT/ROLLBACK semantics, durable storage, access controls, backups, concurrency handling, and operational auditing. Transaction failures propagate to the access layer so callers can fail closed.

## Project structure

```text
access-control/
├── AccessGate.ts
├── AccessPolicy.ts
├── IdentityHasher.ts
├── BlockedIdentityStore.ts
└── TransactionalBlockedIdentityStore.ts

security/
├── SecurityEvent.ts
└── SecurityLogger.ts

tests/
└── access-control/
    ├── AccessGate.test.ts
    ├── PersistentBlockedIdentityStore.test.ts
    └── TransactionalBlockedIdentityStore.test.ts
```

## Scope

Neon Guard can enforce authorization within applications and services controlled by ILLUMYX. It cannot independently disable unrelated accounts, telecommunications numbers, third-party services, or devices.

## Development status

- [x] Access-control architecture
- [x] TypeScript security core
- [x] Keyed HMAC-SHA-256 identity hashing
- [x] In-memory blocked identity store
- [x] Persistent development store
- [x] Deterministic allow/deny gate
- [x] Async authentication gate integration
- [x] Explicit fail-closed decision path
- [x] Security event model
- [x] Unit-test coverage for core decisions
- [x] Production datastore transaction boundary
- [ ] Concrete distributed datastore implementation
- [ ] Android/iOS integration
- [ ] Production security review

## License

Copyright © ILLUMYX. All rights reserved unless a specific file or third-party dependency states otherwise.
