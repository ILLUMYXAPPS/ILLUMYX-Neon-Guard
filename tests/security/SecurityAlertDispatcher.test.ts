import { describe, expect, it } from 'vitest';
import { SecurityAlertDispatcher } from '../../security/SecurityAlertDispatcher';
import type { SecurityAlert } from '../../security/SecurityAlertDispatcher';

class TestChannel {
  readonly alerts: SecurityAlert[] = [];
  deliver(alert: SecurityAlert): void { this.alerts.push(alert); }
}

describe('SecurityAlertDispatcher', () => {
  it('dispatches UNTRUSTED_ACCESS to every configured channel', () => {
    const first = new TestChannel();
    const second = new TestChannel();
    const dispatcher = new SecurityAlertDispatcher([first, second]);

    const alert = dispatcher.dispatch({
      id: 'audit-1', accountId: 'acct-1', type: 'UNTRUSTED_ACCESS',
      timestamp: 100, deviceId: 'unknown-device', reason: 'unknown_device',
    });

    expect(alert?.type).toBe('UNTRUSTED_ACCESS');
    expect(first.alerts).toHaveLength(1);
    expect(second.alerts).toHaveLength(1);
    expect(first.alerts[0].auditEventId).toBe('audit-1');
  });

  it('does not dispatch non-alert audit events', () => {
    const channel = new TestChannel();
    const dispatcher = new SecurityAlertDispatcher([channel]);
    expect(dispatcher.dispatch({
      id: 'audit-2', accountId: 'acct-1', type: 'TRUSTED_ACCESS',
      timestamp: 100, reason: 'trusted_device',
    })).toBeUndefined();
    expect(channel.alerts).toHaveLength(0);
  });
});
