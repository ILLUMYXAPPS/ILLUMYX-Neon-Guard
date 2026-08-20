import { describe, expect, it } from 'vitest';
import { PostgresSecurityAuditStore } from '../../security/PostgresSecurityAuditStore';

function fakeDb() {
  const calls: Array<{ sql: string; params: readonly unknown[] }> = [];
  return {
    calls,
    query: async <T = unknown>(sql: string, params: readonly unknown[] = []) => {
      calls.push({ sql, params });
      return { rows: [] as T[] };
    },
  };
}

describe('PostgresSecurityAuditStore', () => {
  it('uses parameterized SQL and persists the complete audit event', async () => {
    const db = fakeDb();
    const store = new PostgresSecurityAuditStore(db);

    await store.append({
      id: 'evt-1',
      accountId: 'acct-1',
      type: 'UNTRUSTED_ACCESS',
      timestamp: 1750000000000,
      provider: 'test-provider',
      deviceId: 'device-9',
      reason: 'unknown_device',
    });

    expect(db.calls).toHaveLength(1);
    expect(db.calls[0].sql).toContain('ON CONFLICT (id) DO NOTHING');
    expect(db.calls[0].sql).not.toContain('acct-1');
    expect(db.calls[0].params).toEqual([
      'evt-1', 'acct-1', 'UNTRUSTED_ACCESS', 1750000000000,
      'test-provider', 'device-9', 'unknown_device',
    ]);
  });

  it('is idempotent at the SQL boundary for replayed event IDs', async () => {
    const db = fakeDb();
    const store = new PostgresSecurityAuditStore(db);
    const event = {
      id: 'evt-replay',
      accountId: 'acct-1',
      type: 'UNKNOWN_ACCESS' as const,
      timestamp: 1750000000000,
    };

    await store.append(event);
    await store.append(event);

    expect(db.calls).toHaveLength(2);
    expect(db.calls.every(call => call.sql.includes('ON CONFLICT (id) DO NOTHING'))).toBe(true);
  });
});
