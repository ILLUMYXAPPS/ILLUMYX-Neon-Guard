import { createHash } from 'node:crypto';
import { MAX_TRUSTED_DEVICES, TrustedDevice } from './TrustedDeviceRegistry';

export interface StoredTrustedDevice extends TrustedDevice {
  accountId: string;
  tokenDigest?: string;
  lastSeenAt?: number;
}

export interface TrustedDeviceStore {
  list(accountId: string): Promise<StoredTrustedDevice[]>;
  save(device: StoredTrustedDevice): Promise<void>;
  revoke(accountId: string, deviceId: string, revokedAt: number): Promise<void>;
}

/**
 * Persistence adapter with an in-memory reference implementation.
 * Production deployments should replace this adapter with a transactional
 * database implementation while retaining the same security invariants.
 */
export class InMemoryTrustedDeviceStore implements TrustedDeviceStore {
  private readonly records = new Map<string, StoredTrustedDevice>();

  async list(accountId: string): Promise<StoredTrustedDevice[]> {
    return [...this.records.values()]
      .filter((device) => device.accountId === accountId)
      .map((device) => ({ ...device }));
  }

  async save(device: StoredTrustedDevice): Promise<void> {
    if (!device.accountId || !device.deviceId || !device.label) throw new Error('invalid_device');
    const active = [...this.records.values()].filter(
      (record) => record.accountId === device.accountId && record.revokedAt === undefined && record.deviceId !== device.deviceId,
    );
    if (device.revokedAt === undefined && active.length >= MAX_TRUSTED_DEVICES) {
      throw new Error('trusted_device_limit_reached');
    }
    this.records.set(`${device.accountId}:${device.deviceId}`, { ...device });
  }

  async revoke(accountId: string, deviceId: string, revokedAt: number): Promise<void> {
    const key = `${accountId}:${deviceId}`;
    const device = this.records.get(key);
    if (!device) throw new Error('device_not_found');
    this.records.set(key, { ...device, revokedAt });
  }
}

export function tokenDigest(token: string): string {
  return createHash('sha256').update(token, 'utf8').digest('hex');
}
