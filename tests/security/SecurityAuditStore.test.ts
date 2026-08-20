import { describe, expect, it } from 'vitest';
import { InMemorySecurityAuditStore } from '../../security/SecurityAuditStore';

describe('SecurityAuditStore', () => {
  it('persists and isolates events by account', () => {
    const store = new InMemorySecurityAuditStore();
    store.append({ id: '1', accountId: 'a', type: 'UNTRUSTED_ACCESS', timestamp: 1, deviceId: 'd1', reason: 'unknown_device' });
    store.append({ id: '2', accountId: 'b', type: 'TRUSTED_ACCESS', timestamp: 2, deviceId: 'd2', reason: 'trusted_device' });
    expect(store.list('a')).toHaveLength(1);
    expect(store.list('a')[0].id).toBe('1');
  });

  it('rejects duplicate event identifiers', () => {
    const store = new InMemorySecurityAuditStore();
    const event = { id: '1', accountId: 'a', type: 'DEVICE_REGISTERED' as const, timestamp: 1, deviceId: 'd1', reason: 'owner_authorized' };
    store.append(event);
    expect(() => store.append(event)).toThrow('duplicate_audit_event');
  });

  it('rejects malformed audit events', () => {
    const store = new InMemorySecurityAuditStore();
    expect(() => store.append({ id: '', accountId: 'a', type: 'TRUSTED_ACCESS', timestamp: 1, reason: 'x' })).toThrow('invalid_audit_event');
  });
});
