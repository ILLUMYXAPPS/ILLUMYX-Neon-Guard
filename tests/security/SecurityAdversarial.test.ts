import { describe, expect, it } from 'vitest';
import { AccessEventMonitor } from '../../security/AccessEventMonitor';
import { TrustedDeviceRegistry } from '../../security/TrustedDeviceRegistry';
import { TrustedDeviceManager } from '../../security/TrustedDeviceManagement';
import { InMemoryTrustedDeviceStore } from '../../security/TrustedDeviceStore';

describe('security adversarial regression cases', () => {
  it('rejects a fourth active trusted device', () => {
    const registry = new TrustedDeviceRegistry();
    for (let i = 1; i <= 3; i += 1) registry.register({ deviceId: `d${i}`, label: `D${i}`, registeredAt: i });
    expect(() => registry.register({ deviceId: 'd4', label: 'D4', registeredAt: 4 })).toThrow('trusted_device_limit_reached');
  });

  it('does not let a revoked device remain trusted', () => {
    const registry = new TrustedDeviceRegistry();
    registry.register({ deviceId: 'd1', label: 'D1', registeredAt: 1 });
    registry.revoke('d1', 2);
    expect(registry.classify('d1').state).toBe('UNTRUSTED');
  });

  it('does not generate duplicate alerts from a replayed event id', () => {
    const monitor = new AccessEventMonitor(new TrustedDeviceRegistry());
    const event = { eventId: 'replay-1', accountId: 'a', provider: 'test', deviceId: 'bad', timestamp: 1 };
    monitor.ingest(event);
    monitor.ingest(event);
    expect(monitor.getAlerts()).toHaveLength(1);
    expect(monitor.getAuditTrail()).toHaveLength(1);
  });

  it('requires owner authorization for device registration', async () => {
    const audit: unknown[] = [];
    const manager = new TrustedDeviceManager(
      new InMemoryTrustedDeviceStore(),
      { authorize: async () => false },
      { record: (event) => audit.push(event) },
    );
    await expect(manager.register({ accountId: 'a', deviceId: 'd1', label: 'D1', registeredAt: 1 }, 'attacker')).rejects.toThrow('owner_authorization_required');
    expect(audit).toHaveLength(1);
  });

  it('does not expose raw token material through token digest output', async () => {
    const { tokenDigest } = await import('../../security/TrustedDeviceStore.js');
    const token = 'super-secret-token';
    const digest = tokenDigest(token);
    expect(digest).not.toContain(token);
    expect(digest).toMatch(/^[a-f0-9]{64}$/);
  });
});
