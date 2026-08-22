import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { Pool } from 'pg';
import { PostgresTrustedDeviceStore } from '../../security/PostgresTrustedDeviceStore';
import { MAX_TRUSTED_DEVICES } from '../../security/TrustedDeviceRegistry';

const databaseUrl = process.env.DATABASE_URL;
const describeIntegration = databaseUrl ? describe : describe.skip;

describeIntegration('PostgresTrustedDeviceStore integration', () => {
  const pool = new Pool({ connectionString: databaseUrl });
  const store = new PostgresTrustedDeviceStore(pool);

  beforeAll(async () => {
    await pool.query('TRUNCATE TABLE trusted_devices');
  });

  afterAll(async () => {
    await pool.end();
  });

  it('persists, lists and revokes trusted devices', async () => {
    const device = {
      accountId: 'device-account',
      deviceId: 'device-1',
      label: 'Primary',
      platform: 'ios',
      registeredAt: 1000,
      tokenDigest: 'a'.repeat(64),
    };

    await store.save(device);
    expect(await store.list(device.accountId)).toEqual([device]);

    await store.revoke(device.accountId, device.deviceId, 2000);
    expect((await store.list(device.accountId))[0].revokedAt).toBe(2000);
  });

  it('enforces the device limit under concurrent registrations', async () => {
    const accountId = 'concurrent-account';
    const devices = Array.from({ length: MAX_TRUSTED_DEVICES + 2 }, (_, index) => ({
      accountId,
      deviceId: `device-${index + 1}`,
      label: `Device ${index + 1}`,
      registeredAt: index + 1,
    }));

    const results = await Promise.allSettled(devices.map(device => store.save(device)));
    const fulfilled = results.filter(result => result.status === 'fulfilled');
    const rejected = results.filter(result => result.status === 'rejected');

    expect(fulfilled).toHaveLength(MAX_TRUSTED_DEVICES);
    expect(rejected).toHaveLength(2);
    expect(rejected.every(result => result.status === 'rejected' && result.reason instanceof Error && result.reason.message === 'trusted_device_limit_reached')).toBe(true);
    expect((await store.list(accountId)).filter(device => device.revokedAt === undefined)).toHaveLength(MAX_TRUSTED_DEVICES);
  });

  it('atomically replaces an active device', async () => {
    const accountId = 'replacement-account';
    await store.save({ accountId, deviceId: 'old', label: 'Old', registeredAt: 1 });

    await store.replace('old', { accountId, deviceId: 'new', label: 'New', registeredAt: 2 }, 3);

    const devices = await store.list(accountId);
    expect(devices.find(device => device.deviceId === 'old')?.revokedAt).toBe(3);
    expect(devices.find(device => device.deviceId === 'new')?.revokedAt).toBeUndefined();
  });
});
