import { describe, expect, it, vi } from 'vitest';
import { UnauthorisedLoginMonitor } from '../../security/UnauthorisedLoginMonitor';

describe('UnauthorisedLoginMonitor', () => {
  it('allows a recognised device without alerting', () => {
    const monitor = new UnauthorisedLoginMonitor();
    const alert = vi.fn();
    monitor.registerRecognisedDevice('device-1', 'Recognised iPhone');
    monitor.onUnauthorisedLogin(alert);

    expect(monitor.evaluate({ identityKind: 'account', deviceId: 'device-1' })).toBe(true);
    expect(alert).not.toHaveBeenCalled();
  });

  it('alerts when an unrecognised device attempts login', () => {
    const monitor = new UnauthorisedLoginMonitor();
    const alert = vi.fn();
    monitor.onUnauthorisedLogin(alert);

    expect(monitor.evaluate({
      identityKind: 'account',
      deviceId: 'unknown-1',
      deviceLabel: 'Unknown iPhone',
      platform: 'iOS',
      timestamp: '2026-08-22T11:00:00.000Z',
    })).toBe(false);

    expect(alert).toHaveBeenCalledWith(expect.objectContaining({
      type: 'unauthorised_login',
      deviceId: 'unknown-1',
      reason: 'unrecognised_device',
    }));
  });

  it('stops alerting after a device is explicitly recognised', () => {
    const monitor = new UnauthorisedLoginMonitor();
    const alert = vi.fn();
    monitor.onUnauthorisedLogin(alert);

    expect(monitor.evaluate({ identityKind: 'account', deviceId: 'device-2' })).toBe(false);
    monitor.registerRecognisedDevice('device-2', 'Approved device');
    expect(monitor.evaluate({ identityKind: 'account', deviceId: 'device-2' })).toBe(true);
    expect(alert).toHaveBeenCalledTimes(1);
  });
});
