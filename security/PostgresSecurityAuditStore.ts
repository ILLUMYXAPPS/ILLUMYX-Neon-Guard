import type { SecurityAuditEvent, SecurityAuditStore } from './SecurityAuditStore';

export interface SqlExecutor {
  query<T = unknown>(sql: string, params?: readonly unknown[]): Promise<{ rows: T[] }>;
}

/** PostgreSQL adapter boundary. The caller owns the transaction lifecycle. */
export class PostgresSecurityAuditStore implements SecurityAuditStore {
  constructor(private readonly db: SqlExecutor) {}

  async append(event: SecurityAuditEvent): Promise<void> {
    await this.db.query(
      `INSERT INTO security_audit_events
       (id, account_id, event_type, occurred_at, provider, device_id, reason)
       VALUES ($1, $2, $3, to_timestamp($4 / 1000.0), $5, $6, $7)
       ON CONFLICT (id) DO NOTHING`,
      [event.id, event.accountId, event.type, event.timestamp, event.provider ?? null, event.deviceId ?? null, event.reason ?? null],
    );
  }
}
