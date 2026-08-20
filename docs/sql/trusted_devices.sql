-- PostgreSQL production schema for TrustedDeviceStore.
-- Mutations must run in a transaction and acquire the account-scoped
-- pg_advisory_xact_lock used by PostgresTrustedDeviceStore before enforcing
-- the active-device limit.

CREATE TABLE IF NOT EXISTS trusted_devices (
  account_id TEXT NOT NULL,
  device_id TEXT NOT NULL,
  label TEXT NOT NULL,
  platform TEXT,
  registered_at BIGINT NOT NULL,
  revoked_at BIGINT,
  last_seen_at BIGINT,
  token_digest CHAR(64),
  PRIMARY KEY (account_id, device_id),
  CHECK (revoked_at IS NULL OR revoked_at >= registered_at),
  CHECK (token_digest IS NULL OR token_digest ~ '^[0-9a-f]{64}$')
);

CREATE INDEX IF NOT EXISTS trusted_devices_active_idx
  ON trusted_devices (account_id)
  WHERE revoked_at IS NULL;

CREATE INDEX IF NOT EXISTS trusted_devices_token_digest_idx
  ON trusted_devices (account_id, token_digest)
  WHERE token_digest IS NOT NULL;
