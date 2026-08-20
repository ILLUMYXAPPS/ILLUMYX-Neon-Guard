import type { SecurityAuditEvent } from './SecurityAuditStore';

export interface SecurityAlert {
  type: 'UNTRUSTED_ACCESS';
  accountId: string;
  auditEventId: string;
  timestamp: number;
  reason: string;
}

export interface SecurityAlertChannel {
  deliver(alert: SecurityAlert): void;
}

export class SecurityAlertDispatcher {
  constructor(private readonly channels: readonly SecurityAlertChannel[]) {}

  dispatch(event: SecurityAuditEvent): SecurityAlert | undefined {
    if (event.type !== 'UNTRUSTED_ACCESS') return undefined;

    const alert: SecurityAlert = {
      type: 'UNTRUSTED_ACCESS',
      accountId: event.accountId,
      auditEventId: event.id,
      timestamp: event.timestamp,
      reason: event.reason,
    };

    for (const channel of this.channels) channel.deliver(alert);
    return alert;
  }
}
