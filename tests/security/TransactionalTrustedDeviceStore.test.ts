import { describe, expect, it } from 'vitest';
import { TransactionalTrustedDeviceStoreAdapter, TrustedDeviceTransaction } from '../../security/TransactionalTrustedDeviceStore';
import type { StoredTrustedDevice } from '../../security/TrustedDeviceStore';

class FakeTransaction implements TrustedDeviceTransaction {
  private readonly records = new Map<string, StoredTrustedDevice>();
  async list(accountId: string): Promise<StoredTrustedDevice[]> {
    return [...this.records.values()].filter(d => d.accountId === accountId).map(d => ({ ...d }));
  }
  async save(device: StoredTrustedDevice): Promise<void> {
    this.records.set(`${device.accountId}:${device.deviceId}`, { ...device });
  }
  async revoke(accountId: string, deviceId: string, revokedAt: number): Promise<void> {
    const key = `${accountId}:${deviceId}`;
    const current = this.records.get(key);
    if (!current) throw new Error('device_not_found');
    this.records.set(key, { ...current, revokedAt });
  }
}

describe('TransactionalTrustedDeviceStoreAdapter', () => {
  it('checks the three-device invariant inside the transaction', async () => {
    const tx = new FakeTransaction();
    const store = new TransactionalTrustedDeviceStoreAdapter(work => work(tx));
    for (let i = 1; i <= 3; i += 1) {
      await store.save({ accountId: 'acct', deviceId: `d${i}`, label: `Device ${i}`, registeredAt: i });
    }
    await expect(store.save({ accountId: 'acct', deviceId: 'd4', label: 'Device 4', registeredAt: 4 }))
      .rejects.toThrow('trusted_device_limit_reached');
  });

  it('allows a replacement after revocation', async () => {
    const tx = new FakeTransaction();
    const store = new TransactionalTrustedDeviceStoreAdapter(work => work(tx));
    await store.save({ accountId: 'acct', deviceId: 'd1', label: 'Device 1', registeredAt: 1 });
    await store.revoke('acct', 'd1', 2);
    await expect(store.save({ accountId: 'acct', deviceId: 'd2', label: 'Device 2', registeredAt: 3 })).resolves.toBeUndefined();
  });
});
