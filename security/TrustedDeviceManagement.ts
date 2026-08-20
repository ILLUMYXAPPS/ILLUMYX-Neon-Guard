import type { StoredTrustedDevice, TrustedDeviceStore } from './TrustedDeviceStore';

export interface OwnerAuthorizationContext {
  accountId: string;
  actorId: string;
  operation: 'REGISTER_DEVICE' | 'REVOKE_DEVICE' | 'REPLACE_DEVICE';
}

export interface OwnerAuthorizer {
  authorize(context: OwnerAuthorizationContext): Promise<boolean>;
}

export interface DeviceManagementAuditEvent {
  type: 'trusted_device_registered' | 'trusted_device_revoked' | 'trusted_device_replaced' | 'trusted_device_denied';
  accountId: string;
  actorId: string;
  deviceId?: string;
  replacementDeviceId?: string;
  timestamp: number;
}

export interface DeviceManagementAuditSink {
  record(event: DeviceManagementAuditEvent): void;
}

export class TrustedDeviceManager {
  constructor(
    private readonly store: TrustedDeviceStore,
    private readonly ownerAuthorizer: OwnerAuthorizer,
    private readonly audit: DeviceManagementAuditSink,
    private readonly clock: () => number = () => Date.now(),
  ) {}

  async list(accountId: string): Promise<StoredTrustedDevice[]> {
    return this.store.list(accountId);
  }

  async register(device: StoredTrustedDevice, actorId: string): Promise<void> {
    await this.requireOwner(device.accountId, actorId, 'REGISTER_DEVICE');
    await this.store.save(device);
    this.audit.record({
      type: 'trusted_device_registered',
      accountId: device.accountId,
      actorId,
      deviceId: device.deviceId,
      timestamp: this.clock(),
    });
  }

  async revoke(accountId: string, deviceId: string, actorId: string): Promise<void> {
    await this.requireOwner(accountId, actorId, 'REVOKE_DEVICE');
    await this.store.revoke(accountId, deviceId, this.clock());
    this.audit.record({
      type: 'trusted_device_revoked',
      accountId,
      actorId,
      deviceId,
      timestamp: this.clock(),
    });
  }

  async replace(oldDeviceId: string, replacement: StoredTrustedDevice, actorId: string): Promise<void> {
    if (replacement.deviceId === oldDeviceId) throw new Error('replacement_must_be_new_device');
    await this.requireOwner(replacement.accountId, actorId, 'REPLACE_DEVICE');
    await this.store.revoke(replacement.accountId, oldDeviceId, this.clock());
    try {
      await this.store.save(replacement);
    } catch (error) {
      throw error;
    }
    this.audit.record({
      type: 'trusted_device_replaced',
      accountId: replacement.accountId,
      actorId,
      deviceId: oldDeviceId,
      replacementDeviceId: replacement.deviceId,
      timestamp: this.clock(),
    });
  }

  private async requireOwner(accountId: string, actorId: string, operation: OwnerAuthorizationContext['operation']): Promise<void> {
    if (!accountId || !actorId) throw new Error('missing_owner_authorization_context');
    const allowed = await this.ownerAuthorizer.authorize({ accountId, actorId, operation });
    if (!allowed) {
      this.audit.record({ type: 'trusted_device_denied', accountId, actorId, timestamp: this.clock() });
      throw new Error('owner_authorization_required');
    }
  }
}
