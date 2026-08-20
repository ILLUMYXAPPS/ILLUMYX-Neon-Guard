import type { SecurityAuditStore, SecurityAuditEvent } from './SecurityAuditStore';

export interface SecurityAuditSink {
  record(event: SecurityAuditEvent): void;
}

export class PersistentSecurityAuditSink implements SecurityAuditSink {
  constructor(private readonly store: SecurityAuditStore) {}

  record(event: SecurityAuditEvent): void {
    this.store.append(event);
  }
}
