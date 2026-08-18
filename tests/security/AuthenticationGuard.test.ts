import { describe, expect, it } from 'vitest';
import { AccessGate } from '../../access-control/AccessGate';
import { BlockedIdentityStore } from '../../access-control/BlockedIdentityStore';
import { authorizeAuthentication } from '../../security/AuthenticationGuard';

describe('authorizeAuthentication', () => {
  it('returns DENY before a session can be accepted', async () => {
    const store = new BlockedIdentityStore('test-only-secret');
    store.add('+61 400 123 456');

    const decision = await authorizeAuthentication(
      new AccessGate(store),
      { kind: 'phone', identifier: '+61 400 123 456' },
    );

    expect(decision).toEqual({ allowed: false, reason: 'blocked_identity' });
  });
});
