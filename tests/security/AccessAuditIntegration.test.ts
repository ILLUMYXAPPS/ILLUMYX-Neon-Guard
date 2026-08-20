import { describe, expect, it } from 'vitest';
import { AccessEventMonitor } from '../../security/AccessEventMonitor';
import { SecurityAlertDispatcher, type SecurityAlert } from '../../security/SecurityAlertDispatcher';
import { InMemorySecurityAuditStore } from '../../security/SecurityAuditStore';
import { TrustedDeviceRegistry } from '../../security/TrustedDeviceRegistry';

class TestChannel {
  readonly alerts: SecurityAlert[] = [];
  deliver(alert: SecurityAlert): void { this.alerts.push(alert); }
}

describe('Access audit integration', () => {
  it('persists trusted access without alerting', () => {
    const registry = new TrustedDeviceRegistry();
    registry.register({ deviceId: 'trusted-1', label: 'Primary', registeredAt: 1 });
    const store = new InMemorySecurityAuditStore();
    const channel = new TestChannel();
    const monitor = new AccessEventMonitor(registry, store, new SecurityAlertDispatcher([channel]));

    monitor.ingest({ eventId: 'evt-1', accountId: 'acct', provider: 'test', deviceId: 'trusted-1', timestamp: 10 });

    expect(store.list('acct')[0].type).toBe('TRUSTED_ACCESS');
    expect(channel.alerts).toHaveLength(0);
  });

  it('persists untrusted access and dispatches exactly one alert', () => {
    const store = new InMemorySecurityAuditStore();
    const channel = new TestChannel();
    const monitor = new AccessEventMonitor(new TrustedDeviceRegistry(), store, new SecurityAlertDispatcher([channel]));
    const event = { eventId: 'evt-2', accountId: 'acct', provider: 'test', deviceId: 'other', timestamp: 20 };

    monitor.ingest(event);
    monitor.ingest(event);

    expect(store.list('acct')).toHaveLength(1);
    expect(store.list('acct')[0].type).toBe('UNTRUSTED_ACCESS');
    expect(channel.alerts).toHaveLength(1);
  });
});
