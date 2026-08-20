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
  replace(oldDeviceId: string, replacement: StoredTrustedDevice, timestamp: number): Promise<void>;
}

/**
 * Persistence adapter with an in-memory reference implementation.
 * Production deployments should implement replace() as one database transaction
 * so revocation and replacement either both commit or neither does.
 */
export class InMemoryTrustedDeviceStore implements TrustedDeviceStore {
  private readonly records = new Map<string, StoredTrustedDevice>();

  async list(accountId: string): Promise<StoredTrustedDevice[]> {
    return [...this.records.values()]
      .filter((device) => device.accountId === accountId)
      .map((device) => ({ ...device }));
  }

  async save(device: StoredTrustedDevice): Promise<void> {
    this.validate(device);
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

  async replace(oldDeviceId: string, replacement: StoredTrustedDevice, timestamp: number): Promise<void> {
    this.validate(replacement);
    const oldKey = `${replacement.accountId}:${oldDeviceId}`;
    const oldDevice = this.records.get(oldKey);
    if (!oldDevice) throw new Error('device_not_found');
    if (oldDevice.revokedAt !== undefined) throw new Error('device_already_revoked');
    if (replacement.deviceId === oldDeviceId) throw new Error('replacement_must_be_new_device');

    const replacementKey = `${replacement.accountId}:${replacement.deviceId}`;
    if (this.records.has(replacementKey)) throw new Error('replacement_device_already_exists');

    // Validate everything before mutating either record. In the production
    // adapter this entire operation must execute inside one DB transaction.
    const nextOld = { ...oldDevice, revokedAt: timestamp };
    const nextReplacement = { ...replacement };
    this.records.set(oldKey, nextOld);
    try {
      this.records.set(replacementKey, nextReplacement);
    } catch (error) {
      this.records.set(oldKey, oldDevice);
      throw error;
    }
  }

  private validate(device: StoredTrustedDevice): void {
    if (!device.accountId || !device.deviceId || !device.label) throw new Error('invalid_device');
  }
}

export function tokenDigest(token: string): string {
  return createHash('sha256').update(token, 'utf8').digest('hex');
}
