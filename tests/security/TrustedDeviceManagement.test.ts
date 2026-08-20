import { describe, expect, it } from 'vitest';
import { TrustedDeviceManager } from '../../security/TrustedDeviceManagement';
import { InMemoryTrustedDeviceStore } from '../../security/TrustedDeviceStore';

describe('TrustedDeviceManager', () => {
  const device = (id: string) => ({ accountId: 'acct', deviceId: id, label: id, registeredAt: 1 });

  it('rejects registration without owner authorization', async () => {
    const audit: any[] = [];
    const manager = new TrustedDeviceManager(
      new InMemoryTrustedDeviceStore(),
      { authorize: async () => false },
      { record: (event) => audit.push(event) },
    );
    await expect(manager.register(device('device-1'), 'actor-x')).rejects.toThrow('owner_authorization_required');
    expect(audit[0].type).toBe('trusted_device_denied');
  });

  it('allows registration after owner authorization', async () => {
    const store = new InMemoryTrustedDeviceStore();
    const audit: any[] = [];
    const manager = new TrustedDeviceManager(
      store,
      { authorize: async () => true },
      { record: (event) => audit.push(event) },
      () => 100,
    );
    await manager.register(device('device-1'), 'owner');
    expect(await manager.list('acct')).toHaveLength(1);
    expect(audit[0]).toMatchObject({ type: 'trusted_device_registered', actorId: 'owner', deviceId: 'device-1', timestamp: 100 });
  });

  it('requires owner authorization for revocation', async () => {
    const store = new InMemoryTrustedDeviceStore();
    await store.save(device('device-1'));
    const manager = new TrustedDeviceManager(store, { authorize: async () => false }, { record: () => undefined });
    await expect(manager.revoke('acct', 'device-1', 'actor-x')).rejects.toThrow('owner_authorization_required');
    expect((await store.list('acct'))[0].revokedAt).toBeUndefined();
  });

  it('replaces a device only after authorization', async () => {
    const store = new InMemoryTrustedDeviceStore();
    await store.save(device('device-1'));
    const audit: any[] = [];
    const manager = new TrustedDeviceManager(store, { authorize: async () => true }, { record: (event) => audit.push(event) }, () => 200);
    await manager.replace('device-1', device('device-2'), 'owner');
    const records = await store.list('acct');
    expect(records.find((d) => d.deviceId === 'device-1')?.revokedAt).toBe(200);
    expect(records.find((d) => d.deviceId === 'device-2')?.revokedAt).toBeUndefined();
    expect(audit[0]).toMatchObject({ type: 'trusted_device_replaced', deviceId: 'device-1', replacementDeviceId: 'device-2' });
  });
});
