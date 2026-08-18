import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { AccessGate } from '../../access-control/AccessGate';
import { PersistentBlockedIdentityStore } from '../../access-control/BlockedIdentityStore';

const secret = 'test-only-secret';
const phone = '+61 400 123 456';

describe('PersistentBlockedIdentityStore', () => {
  it('persists a blocked identity across store instances', async () => {
    const directory = await mkdtemp(join(tmpdir(), 'neon-guard-'));
    const path = join(directory, 'blocked.json');

    try {
      const first = new PersistentBlockedIdentityStore(path, secret);
      await first.add(phone);

      const second = new PersistentBlockedIdentityStore(path, secret);
      expect(await second.has(' +61 400 123 456 ')).toBe(true);
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  });

  it('survives a process-level store restart and removes an identity', async () => {
    const directory = await mkdtemp(join(tmpdir(), 'neon-guard-'));
    const path = join(directory, 'blocked.json');

    try {
      const first = new PersistentBlockedIdentityStore(path, secret);
      await first.add(phone);
      await first.remove(phone);

      const second = new PersistentBlockedIdentityStore(path, secret);
      expect(await second.has(phone)).toBe(false);
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  });

  it('uses the persistent store through the async access gate', async () => {
    const directory = await mkdtemp(join(tmpdir(), 'neon-guard-'));
    const path = join(directory, 'blocked.json');

    try {
      const store = new PersistentBlockedIdentityStore(path, secret);
      await store.add(phone);
      const gate = new AccessGate(store);
      await expect(gate.evaluateAsync({ kind: 'phone', identifier: phone })).resolves.toEqual({
        allowed: false,
        reason: 'blocked_identity',
      });
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  });
});
