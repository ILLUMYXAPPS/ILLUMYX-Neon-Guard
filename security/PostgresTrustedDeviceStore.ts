import type { Pool, PoolClient } from 'pg';
import { MAX_TRUSTED_DEVICES } from './TrustedDeviceRegistry';
import type { StoredTrustedDevice, TrustedDeviceStore } from './TrustedDeviceStore';
import type { TrustedDeviceTransaction } from './TransactionalTrustedDeviceStore';

export interface PostgresTrustedDeviceStoreOptions {
  maxTrustedDevices?: number;
}

type Db = Pick<Pool, 'connect'>;

/**
 * Production PostgreSQL trusted-device adapter.
 * Every mutation serializes on an account-scoped transaction advisory lock before
 * checking the active-device count, preventing concurrent registrations from
 * bypassing MAX_TRUSTED_DEVICES.
 */
export class PostgresTrustedDeviceStore implements TrustedDeviceStore {
  private readonly maxTrustedDevices: number;

  constructor(private readonly db: Db, options: PostgresTrustedDeviceStoreOptions = {}) {
    this.maxTrustedDevices = options.maxTrustedDevices ?? MAX_TRUSTED_DEVICES;
  }

  async list(accountId: string): Promise<StoredTrustedDevice[]> {
    const client = await this.db.connect();
    try {
      return await this.listWithClient(client, accountId);
    } finally {
      client.release();
    }
  }

  async save(device: StoredTrustedDevice): Promise<void> {
    this.validate(device);
    await this.withTransaction(async client => {
      await this.lockAccount(client, device.accountId);
      const existing = await client.query(
        `SELECT revoked_at FROM trusted_devices WHERE account_id = $1 AND device_id = $2`,
        [device.accountId, device.deviceId],
      );
      if (device.revokedAt === undefined) {
        const active = await this.activeCount(client, device.accountId, device.deviceId);
        if (active >= this.maxTrustedDevices && existing.rowCount === 0) {
          throw new Error('trusted_device_limit_reached');
        }
      }
      await this.upsert(client, device);
    });
  }

  async revoke(accountId: string, deviceId: string, revokedAt: number): Promise<void> {
    await this.withTransaction(async client => {
      await this.lockAccount(client, accountId);
      const result = await client.query(
        `UPDATE trusted_devices SET revoked_at = $3 WHERE account_id = $1 AND device_id = $2`,
        [accountId, deviceId, revokedAt],
      );
      if (result.rowCount === 0) throw new Error('device_not_found');
    });
  }

  async replace(oldDeviceId: string, replacement: StoredTrustedDevice, timestamp: number): Promise<void> {
    this.validate(replacement);
    await this.withTransaction(async client => {
      await this.lockAccount(client, replacement.accountId);
      const old = await client.query(
        `SELECT device_id, revoked_at FROM trusted_devices WHERE account_id = $1 AND device_id = $2 FOR UPDATE`,
        [replacement.accountId, oldDeviceId],
      );
      if (old.rowCount === 0) throw new Error('device_not_found');
      if (old.rows[0].revoked_at !== null) throw new Error('device_already_revoked');
      if (oldDeviceId === replacement.deviceId) throw new Error('replacement_must_be_new_device');
      const duplicate = await client.query(
        `SELECT 1 FROM trusted_devices WHERE account_id = $1 AND device_id = $2`,
        [replacement.accountId, replacement.deviceId],
      );
      if (duplicate.rowCount !== 0) throw new Error('replacement_device_already_exists');

      await client.query(
        `UPDATE trusted_devices SET revoked_at = $3 WHERE account_id = $1 AND device_id = $2`,
        [replacement.accountId, oldDeviceId, timestamp],
      );
      await this.insert(client, replacement);
    });
  }

  private async withTransaction<T>(work: (client: PoolClient) => Promise<T>): Promise<T> {
    const client = await this.db.connect();
    try {
      await client.query('BEGIN');
      const result = await work(client);
      await client.query('COMMIT');
      return result;
    } catch (error) {
      await client.query('ROLLBACK');
      throw error;
    } finally {
      client.release();
    }
  }

  private async lockAccount(client: PoolClient, accountId: string): Promise<void> {
    await client.query('SELECT pg_advisory_xact_lock(hashtext($1))', [accountId]);
  }

  private async activeCount(client: PoolClient, accountId: string, excludeDeviceId?: string): Promise<number> {
    const result = await client.query(
      `SELECT COUNT(*)::int AS count FROM trusted_devices
       WHERE account_id = $1 AND revoked_at IS NULL AND ($2::text IS NULL OR device_id <> $2)`,
      [accountId, excludeDeviceId ?? null],
    );
    return Number(result.rows[0].count);
  }

  private async listWithClient(client: PoolClient, accountId: string): Promise<StoredTrustedDevice[]> {
    const result = await client.query(
      `SELECT account_id, device_id, label, platform, registered_at, revoked_at, last_seen_at, token_digest
       FROM trusted_devices WHERE account_id = $1 ORDER BY registered_at ASC, device_id ASC`,
      [accountId],
    );
    return result.rows.map(row => ({
      accountId: row.account_id,
      deviceId: row.device_id,
      label: row.label,
      platform: row.platform ?? undefined,
      registeredAt: Number(row.registered_at),
      revokedAt: row.revoked_at === null ? undefined : Number(row.revoked_at),
      lastSeenAt: row.last_seen_at === null ? undefined : Number(row.last_seen_at),
      tokenDigest: row.token_digest ?? undefined,
    }));
  }

  private async upsert(client: PoolClient, device: StoredTrustedDevice): Promise<void> {
    await client.query(
      `INSERT INTO trusted_devices
       (account_id, device_id, label, platform, registered_at, revoked_at, last_seen_at, token_digest)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
       ON CONFLICT (account_id, device_id) DO UPDATE SET
         label = EXCLUDED.label,
         platform = EXCLUDED.platform,
         registered_at = EXCLUDED.registered_at,
         revoked_at = EXCLUDED.revoked_at,
         last_seen_at = EXCLUDED.last_seen_at,
         token_digest = EXCLUDED.token_digest`,
      [device.accountId, device.deviceId, device.label, device.platform ?? null, device.registeredAt,
        device.revokedAt ?? null, device.lastSeenAt ?? null, device.tokenDigest ?? null],
    );
  }

  private async insert(client: PoolClient, device: StoredTrustedDevice): Promise<void> {
    await client.query(
      `INSERT INTO trusted_devices
       (account_id, device_id, label, platform, registered_at, revoked_at, last_seen_at, token_digest)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
      [device.accountId, device.deviceId, device.label, device.platform ?? null, device.registeredAt,
        device.revokedAt ?? null, device.lastSeenAt ?? null, device.tokenDigest ?? null],
    );
  }

  private validate(device: StoredTrustedDevice): void {
    if (!device.accountId || !device.deviceId || !device.label) throw new Error('invalid_device');
  }
}
