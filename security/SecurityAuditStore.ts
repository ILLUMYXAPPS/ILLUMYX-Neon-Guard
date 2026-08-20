export type AuditEventType =
  | 'TRUSTED_ACCESS'
  | 'UNKNOWN_ACCESS'
  | 'UNTRUSTED_ACCESS'
  | 'DEVICE_REGISTERED'
  | 'DEVICE_REVOKED'
  | 'DEVICE_REPLACED'
  | 'DEVICE_CHANGE_DENIED';

export interface SecurityAuditEvent {
  id: string;
  accountId: string;
  type: AuditEventType;
  timestamp: number;
  provider?: string;
  deviceId?: string;
  reason: string;
}

/**
 * Production implementations must provide durable, transactional storage.
 * The reference adapter is intentionally process-local and is not production persistence.
 */
export interface SecurityAuditStore {
  append(event: SecurityAuditEvent): void;
  list(accountId: string): readonly SecurityAuditEvent[];
}

export class InMemorySecurityAuditStore implements SecurityAuditStore {
  private readonly events: SecurityAuditEvent[] = [];

  append(event: SecurityAuditEvent): void {
    if (!event.id || !event.accountId || !event.type || !event.reason) {
      throw new Error('invalid_audit_event');
    }
    if (this.events.some((existing) => existing.id === event.id)) {
      throw new Error('duplicate_audit_event');
    }
    this.events.push({ ...event });
  }

  list(accountId: string): readonly SecurityAuditEvent[] {
    return this.events
      .filter((event) => event.accountId === accountId)
      .map((event) => ({ ...event }));
  }
}
