import { generateKeyPairSync, sign } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { CANONICAL_OWNER, authorizeOwnershipChange } from '../../security/OwnershipControl';
import { InMemorySecurityLogger } from '../../security/SecurityLogger';

describe('authorizeOwnershipChange', () => {
  it('allows a correctly signed owner-authorized change using the trusted registry key', () => {
    const { privateKey, publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
    const current = { ownerId: 'aaron-owner', ownerDisplayName: CANONICAL_OWNER, version: 1 };
    const requested = { ...current, ownerDisplayName: CANONICAL_OWNER };
    const payload = JSON.stringify({ ownerId: current.ownerId, version: current.version, requested });
    const signature = sign('SHA256', Buffer.from(payload), privateKey).toString('base64');
    const logger = new InMemorySecurityLogger();
    const registry = { getPublicKeyPem: (ownerId: string) => ownerId === current.ownerId ? publicKey.export({ type: 'pkcs1', format: 'pem' }).toString() : undefined };

    const decision = authorizeOwnershipChange(current, requested, { ownerId: current.ownerId, payload, signature }, registry, logger);

    expect(decision.allowed).toBe(true);
    expect(decision.state.version).toBe(2);
  });

  it('rejects a signature made by an untrusted key', () => {
    const { privateKey: trustedPrivateKey, publicKey: trustedPublicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
    const { privateKey: attackerPrivateKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
    const current = { ownerId: 'aaron-owner', ownerDisplayName: CANONICAL_OWNER, version: 1 };
    const requested = { ...current };
    const payload = JSON.stringify({ ownerId: current.ownerId, version: current.version, requested });
    const signature = sign('SHA256', Buffer.from(payload), attackerPrivateKey).toString('base64');
    const logger = new InMemorySecurityLogger();
    const registry = { getPublicKeyPem: () => trustedPublicKey.export({ type: 'pkcs1', format: 'pem' }).toString() };

    const decision = authorizeOwnershipChange(current, requested, { ownerId: current.ownerId, payload, signature }, registry, logger);

    expect(decision).toEqual({ allowed: false, reason: 'invalid_signature', state: current });
    expect(logger.events.at(-1)?.type).toBe('access_denied');
    void trustedPrivateKey;
  });

  it('rejects a payload that is not bound to the requested state', () => {
    const { privateKey, publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
    const current = { ownerId: 'aaron-owner', ownerDisplayName: CANONICAL_OWNER, version: 1 };
    const requested = { ...current };
    const signedPayload = JSON.stringify({ ownerId: current.ownerId, version: current.version, requested: current });
    const signature = sign('SHA256', Buffer.from(signedPayload), privateKey).toString('base64');
    const logger = new InMemorySecurityLogger();
    const registry = { getPublicKeyPem: () => publicKey.export({ type: 'pkcs1', format: 'pem' }).toString() };
    const tamperedRequested = { ...current, ownerDisplayName: 'Tampered' };

    const decision = authorizeOwnershipChange(current, tamperedRequested, { ownerId: current.ownerId, payload: signedPayload, signature }, registry, logger);

    expect(decision.allowed).toBe(false);
    expect(decision.reason).toBe('invalid_payload');
  });
});
