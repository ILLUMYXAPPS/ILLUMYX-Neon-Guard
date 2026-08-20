export type DeviceTrustState = 'TRUSTED' | 'UNKNOWN' | 'UNTRUSTED';

export interface TrustedDevice {
  deviceId: string;
  label: string;
  platform?: string;
  registeredAt: number;
  revokedAt?: number;
}

export interface AccessEvent {
  accountId: string;
  provider: string;
  deviceId?: string;
  platform?: string;
  timestamp: number;
}

export interface DeviceClassification {
  state: DeviceTrustState;
  reason: 'trusted_device' | 'known_untrusted_device' | 'missing_device_metadata' | 'unknown_device';
}

export const MAX_TRUSTED_DEVICES = 3;

export class TrustedDeviceRegistry {
  private readonly devices = new Map<string, TrustedDevice>();

  register(device: TrustedDevice): void {
    if (!device.deviceId || !device.label) throw new Error('invalid_device');
    if (this.devices.has(device.deviceId)) throw new Error('device_already_registered');
    if (this.activeDevices().length >= MAX_TRUSTED_DEVICES) throw new Error('trusted_device_limit_reached');
    this.devices.set(device.deviceId, { ...device });
  }

  revoke(deviceId: string, revokedAt: number): void {
    const device = this.devices.get(deviceId);
    if (!device) throw new Error('device_not_found');
    this.devices.set(deviceId, { ...device, revokedAt });
  }

  activeDevices(): TrustedDevice[] {
    return [...this.devices.values()].filter((device) => device.revokedAt === undefined);
  }

  classify(deviceId?: string): DeviceClassification {
    if (!deviceId) return { state: 'UNKNOWN', reason: 'missing_device_metadata' };
    if (this.activeDevices().some((device) => device.deviceId === deviceId)) {
      return { state: 'TRUSTED', reason: 'trusted_device' };
    }
    if (this.devices.has(deviceId)) return { state: 'UNTRUSTED', reason: 'known_untrusted_device' };
    return { state: 'UNTRUSTED', reason: 'unknown_device' };
  }

  classifyAccess(event: AccessEvent): DeviceClassification {
    return this.classify(event.deviceId);
  }
}
