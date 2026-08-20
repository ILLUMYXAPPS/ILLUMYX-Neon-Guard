import type { SecurityAuditEvent } from './SecurityAuditStore';

export interface SqlExecutor {
  query<T = unknown>(sql: string, params?: readonly unknown[]): Promise<{ rows: T[] }>;
}

export interface AsyncSecurityAuditStore {
  append(event: SecurityAuditEvent): Promise<void>;
  list(accountId: string): Promise<readonly SecurityAuditEvent[]>;
}

/** PostgreSQL adapter boundary. The caller owns the transaction lifecycle. */
export class PostgresSecurityAuditStore implements AsyncSecurityAuditStore {
  constructor(private readonly db: SqlExecutor) {}

  async append(event: SecurityAuditEvent): Promise<void> {
    await this.db.query(
      `INSERT INTO security_audit_events
       (id, account_id, event_type, occurred_at, provider, device_id, reason)
       VALUES ($1, $2, $3, to_timestamp($4 / 1000.0), $5, $6, $7)
       ON CONFLICT (id) DO NOTHING`,
      [event.id, event.accountId, event.type, event.timestamp, event.provider ?? null, event.deviceId ?? null, event.reason],
    );
  }

  async list(accountId: string): Promise<readonly SecurityAuditEvent[]> {
    const result = await this.db.query<{
      id: string;
      account_id: string;
      event_type: SecurityAuditEvent['type'];
      occurred_at: Date;
      provider: string | null;
      device_id: string | null;
      reason: string;
    }>(
      `SELECT id, account_id, event_type, occurred_at, provider, device_id, reason
       FROM security_audit_events
       WHERE account_id = $1
       ORDER BY occurred_at ASC, id ASC`,
      [accountId],
    );

    return result.rows.map(row => ({
      id: row.id,
      accountId: row.account_id,
      type: row.event_type,
      timestamp: row.occurred_at.getTime(),
      provider: row.provider ?? undefined,
      deviceId: row.device_id ?? undefined,
      reason: row.reason,
    }));
  }
}
