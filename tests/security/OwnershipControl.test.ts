import { generateKeyPairSync, sign } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { CANONICAL_OWNER, authorizeOwnershipChange } from '../../security/OwnershipControl';
import { InMemorySecurityLogger } from '../../security/SecurityLogger';

describe('authorizeOwnershipChange', () => {
  it('allows a correctly signed owner-authorized change', () => {
    const { privateKey, publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
    const current = { ownerId: 'aaron-owner', ownerDisplayName: CANONICAL_OWNER, version: 1 };
    const requested = { ...current, ownerDisplayName: 'Aaron Stephen Paszek' };
    const payload = JSON.stringify({ ownerId: current.ownerId, version: current.version, requested });
    const signature = sign('SHA256', Buffer.from(payload), privateKey).toString('base64');
    const logger = new InMemorySecurityLogger();

    const decision = authorizeOwnershipChange(current, requested, { ownerId: current.ownerId, payload, signature, publicKeyPem: publicKey.export({ type: 'pkcs1', format: 'pem' }).toString() }, logger);

    expect(decision.allowed).toBe(true);
    expect(decision.state.version).toBe(2);
  });

  it('rejects a forged ownership signature', () => {
    const { publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
    const current = { ownerId: 'aaron-owner', ownerDisplayName: CANONICAL_OWNER, version: 1 };
    const requested = { ...current };
    const logger = new InMemorySecurityLogger();

    const decision = authorizeOwnershipChange(current, requested, { ownerId: current.ownerId, payload: 'forged', signature: Buffer.from('not-valid').toString('base64'), publicKeyPem: publicKey.export({ type: 'pkcs1', format: 'pem' }).toString() }, logger);

    expect(decision).toEqual({ allowed: false, reason: 'invalid_signature', state: current });
    expect(logger.events.at(-1)?.type).toBe('access_denied');
  });
});
