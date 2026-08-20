import type { StoredTrustedDevice, TrustedDeviceStore } from './TrustedDeviceStore';
import { MAX_TRUSTED_DEVICES } from './TrustedDeviceRegistry';

export interface TrustedDeviceTransaction {
  list(accountId: string): Promise<StoredTrustedDevice[]>;
  save(device: StoredTrustedDevice): Promise<void>;
  revoke(accountId: string, deviceId: string, revokedAt: number): Promise<void>;
}

export interface TransactionalTrustedDeviceStore extends TrustedDeviceStore {
  transaction<T>(work: (tx: TrustedDeviceTransaction) => Promise<T>): Promise<T>;
}

/**
 * Reference wrapper for a transactional persistence adapter.
 * A production adapter must provide an actual database transaction so the
 * three-device invariant cannot be bypassed by concurrent registrations.
 */
export class TransactionalTrustedDeviceStoreAdapter implements TransactionalTrustedDeviceStore {
  constructor(private readonly transactionRunner: <T>(work: (tx: TrustedDeviceTransaction) => Promise<T>) => Promise<T>) {}

  transaction<T>(work: (tx: TrustedDeviceTransaction) => Promise<T>): Promise<T> {
    return this.transactionRunner(work);
  }

  list(accountId: string): Promise<StoredTrustedDevice[]> {
    return this.transaction(tx => tx.list(accountId));
  }

  save(device: StoredTrustedDevice): Promise<void> {
    return this.transaction(async tx => {
      if (!device.accountId || !device.deviceId || !device.label) throw new Error('invalid_device');
      const active = (await tx.list(device.accountId)).filter(
        record => record.revokedAt === undefined && record.deviceId !== device.deviceId,
      );
      if (device.revokedAt === undefined && active.length >= MAX_TRUSTED_DEVICES) {
        throw new Error('trusted_device_limit_reached');
      }
      await tx.save(device);
    });
  }

  revoke(accountId: string, deviceId: string, revokedAt: number): Promise<void> {
    return this.transaction(tx => tx.revoke(accountId, deviceId, revokedAt));
  }
}
