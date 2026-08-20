import { describe, expect, it } from 'vitest';
import { AccessEventMonitor } from '../../security/AccessEventMonitor';
import { TrustedDeviceRegistry } from '../../security/TrustedDeviceRegistry';

describe('AccessEventMonitor', () => {
  it('classifies trusted access without creating an alert', () => {
    const registry = new TrustedDeviceRegistry();
    registry.register({ deviceId: 'trusted-1', label: 'Primary', registeredAt: 1 });
    const monitor = new AccessEventMonitor(registry);

    const result = monitor.ingest({ eventId: 'evt-1', accountId: 'acct', provider: 'test', deviceId: 'trusted-1', timestamp: 10 });
    expect(result.alert).toBeUndefined();
    expect(result.audit?.classification.state).toBe('TRUSTED');
  });

  it('creates UNTRUSTED_ACCESS for a different device', () => {
    const monitor = new AccessEventMonitor(new TrustedDeviceRegistry());
    const result = monitor.ingest({ eventId: 'evt-2', accountId: 'acct', provider: 'test', deviceId: 'other-device', timestamp: 20 });
    expect(result.alert?.type).toBe('UNTRUSTED_ACCESS');
    expect(result.audit?.classification.state).toBe('UNTRUSTED');
  });

  it('preserves UNKNOWN when device metadata is missing', () => {
    const monitor = new AccessEventMonitor(new TrustedDeviceRegistry());
    const result = monitor.ingest({ eventId: 'evt-3', accountId: 'acct', provider: 'test', timestamp: 30 });
    expect(result.alert).toBeUndefined();
    expect(result.audit?.classification.state).toBe('UNKNOWN');
  });

  it('deduplicates repeated provider events', () => {
    const monitor = new AccessEventMonitor(new TrustedDeviceRegistry());
    const event = { eventId: 'evt-4', accountId: 'acct', provider: 'test', deviceId: 'other-device', timestamp: 40 };
    expect(monitor.ingest(event).duplicate).toBe(false);
    expect(monitor.ingest(event).duplicate).toBe(true);
    expect(monitor.getAlerts()).toHaveLength(1);
    expect(monitor.getAuditTrail()).toHaveLength(1);
  });
});
