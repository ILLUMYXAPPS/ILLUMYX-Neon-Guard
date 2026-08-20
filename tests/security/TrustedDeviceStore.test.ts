import { describe, expect, it } from 'vitest';
import { InMemoryTrustedDeviceStore, tokenDigest } from '../../security/TrustedDeviceStore';

describe('TrustedDeviceStore', () => {
  it('enforces three active devices per account', async () => {
    const store = new InMemoryTrustedDeviceStore();
    for (let i = 1; i <= 3; i += 1) {
      await store.save({ accountId: 'acct', deviceId: `device-${i}`, label: `Device ${i}`, registeredAt: i });
    }
    await expect(store.save({ accountId: 'acct', deviceId: 'device-4', label: 'Device 4', registeredAt: 4 }))
      .rejects.toThrow('trusted_device_limit_reached');
  });

  it('allows a revoked slot to be replaced', async () => {
    const store = new InMemoryTrustedDeviceStore();
    for (let i = 1; i <= 3; i += 1) {
      await store.save({ accountId: 'acct', deviceId: `device-${i}`, label: `Device ${i}`, registeredAt: i });
    }
    await store.revoke('acct', 'device-2', 10);
    await store.save({ accountId: 'acct', deviceId: 'device-4', label: 'Replacement', registeredAt: 11 });
    expect((await store.list('acct')).filter((d) => d.revokedAt === undefined)).toHaveLength(3);
  });

  it('keeps account records isolated', async () => {
    const store = new InMemoryTrustedDeviceStore();
    await store.save({ accountId: 'acct-a', deviceId: 'device-1', label: 'A', registeredAt: 1 });
    await store.save({ accountId: 'acct-b', deviceId: 'device-1', label: 'B', registeredAt: 1 });
    expect(await store.list('acct-a')).toHaveLength(1);
    expect(await store.list('acct-b')).toHaveLength(1);
  });

  it('stores a digest rather than requiring the raw token', async () => {
    const token = 'example-secret-token';
    const digest = tokenDigest(token);
    expect(digest).toHaveLength(64);
    expect(digest).not.toBe(token);
  });
});
