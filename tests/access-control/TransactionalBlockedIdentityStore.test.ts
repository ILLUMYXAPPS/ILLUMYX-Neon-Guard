import { describe, expect, it, vi } from 'vitest';
import { TransactionalStoreAdapter } from '../../access-control/TransactionalBlockedIdentityStore';

function store() {
  const values = new Set<string>();
  return {
    add: vi.fn(async (id: string) => { values.add(id); }),
    remove: vi.fn(async (id: string) => { values.delete(id); }),
    has: vi.fn(async (id: string) => values.has(id)),
    clear: vi.fn(async () => { values.clear(); }),
  };
}

describe('TransactionalStoreAdapter', () => {
  it('wraps writes in the supplied transaction boundary', async () => {
    const delegate = store();
    const events: string[] = [];
    const adapter = new TransactionalStoreAdapter(delegate, async (operation) => {
      events.push('begin');
      try {
        const result = await operation();
        events.push('commit');
        return result;
      } catch (error) {
        events.push('rollback');
        throw error;
      }
    });

    await adapter.add('x');
    await adapter.remove('x');
    await adapter.clear();

    expect(events).toEqual(['begin', 'commit', 'begin', 'commit', 'begin', 'commit']);
  });

  it('propagates transaction failures so callers can fail closed', async () => {
    const delegate = store();
    const error = new Error('transaction unavailable');
    const adapter = new TransactionalStoreAdapter(delegate, async () => { throw error; });

    await expect(adapter.add('x')).rejects.toBe(error);
    expect(delegate.add).not.toHaveBeenCalled();
  });
});
