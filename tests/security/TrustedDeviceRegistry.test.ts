import { describe, expect, it } from 'vitest';
import { MAX_TRUSTED_DEVICES, TrustedDeviceRegistry } from '../../security/TrustedDeviceRegistry';

describe('TrustedDeviceRegistry', () => {
  it('allows exactly three active trusted devices', () => {
    const registry = new TrustedDeviceRegistry();
    for (let i = 1; i <= MAX_TRUSTED_DEVICES; i += 1) {
      registry.register({ deviceId: `device-${i}`, label: `Device ${i}`, registeredAt: 1000 });
    }
    expect(registry.activeDevices()).toHaveLength(3);
    expect(() => registry.register({ deviceId: 'device-4', label: 'Device 4', registeredAt: 1000 })).toThrow('trusted_device_limit_reached');
  });

  it('classifies registered devices as trusted', () => {
    const registry = new TrustedDeviceRegistry();
    registry.register({ deviceId: 'device-1', label: 'Primary', registeredAt: 1000 });
    expect(registry.classify('device-1')).toEqual({ state: 'TRUSTED', reason: 'trusted_device' });
  });

  it('classifies missing device metadata as unknown', () => {
    const registry = new TrustedDeviceRegistry();
    expect(registry.classify()).toEqual({ state: 'UNKNOWN', reason: 'missing_device_metadata' });
  });

  it('classifies an unregistered device as untrusted', () => {
    const registry = new TrustedDeviceRegistry();
    expect(registry.classify('device-x')).toEqual({ state: 'UNTRUSTED', reason: 'unknown_device' });
  });

  it('makes a revoked trusted device untrusted', () => {
    const registry = new TrustedDeviceRegistry();
    registry.register({ deviceId: 'device-1', label: 'Primary', registeredAt: 1000 });
    registry.revoke('device-1', 2000);
    expect(registry.classify('device-1')).toEqual({ state: 'UNTRUSTED', reason: 'known_untrusted_device' });
  });
});
