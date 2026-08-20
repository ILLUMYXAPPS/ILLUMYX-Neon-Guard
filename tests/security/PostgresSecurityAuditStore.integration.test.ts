import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { Pool } from 'pg';
import { PostgresSecurityAuditStore } from '../../security/PostgresSecurityAuditStore';

const databaseUrl = process.env.DATABASE_URL;
const describeIntegration = databaseUrl ? describe : describe.skip;

describeIntegration('PostgresSecurityAuditStore integration', () => {
  const pool = new Pool({ connectionString: databaseUrl });
  const store = new PostgresSecurityAuditStore(pool);

  beforeAll(async () => {
    await pool.query('TRUNCATE TABLE security_audit_events');
  });

  afterAll(async () => {
    await pool.end();
  });

  it('persists and deduplicates a security audit event in PostgreSQL', async () => {
    const event = {
      id: 'integration-event-1',
      accountId: 'integration-account',
      type: 'UNTRUSTED_ACCESS' as const,
      timestamp: 1750000000000,
      provider: 'integration-provider',
      deviceId: 'integration-device',
      reason: 'unknown_device',
    };

    await store.append(event);
    await store.append(event);

    const result = await pool.query(
      'SELECT id, account_id, event_type, provider, device_id, reason FROM security_audit_events WHERE id = $1',
      [event.id],
    );

    expect(result.rows).toEqual([{
      id: event.id,
      account_id: event.accountId,
      event_type: event.type,
      provider: event.provider,
      device_id: event.deviceId,
      reason: event.reason,
    }]);
  });
});
