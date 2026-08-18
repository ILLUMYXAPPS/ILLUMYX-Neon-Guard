import { describe, expect, it } from 'vitest';
import { AccessGate } from '../../access-control/AccessGate';
import { BlockedIdentityStore } from '../../access-control/BlockedIdentityStore';
const phone = '+61 400 123 456';
describe('AccessGate', () => {
  it('allows an identity that is not blocked', () => {
    const gate = new AccessGate(new BlockedIdentityStore());
    expect(gate.evaluate({ kind: 'phone', identifier: phone })).toEqual({ allowed: true, reason: 'not_blocked' });
  });
  it('denies a blocked identity after normalization', () => {
    const store = new BlockedIdentityStore(); store.add(phone); const gate = new AccessGate(store);
    expect(gate.evaluate({ kind: 'phone', identifier: ' +61 400 123 456 ' })).toEqual({ allowed: false, reason: 'blocked_identity' });
  });
  it('can deny an entire configured identity kind', () => {
    const gate = new AccessGate(new BlockedIdentityStore(), { denyKinds: new Set(['device']) });
    expect(gate.evaluate({ kind: 'device', identifier: 'device-1' })).toEqual({ allowed: false, reason: 'blocked_kind' });
  });
});
