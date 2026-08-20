-- PostgreSQL reference schema for the production TrustedDeviceStore adapter.
-- The application must use a transaction and lock the account's active rows
-- before enforcing the three-device limit.

CREATE TABLE IF NOT EXISTS trusted_devices (
  account_id TEXT NOT NULL,
  device_id TEXT NOT NULL,
  label TEXT NOT NULL,
  platform TEXT,
  registered_at BIGINT NOT NULL,
  revoked_at BIGINT,
  last_seen_at BIGINT,
  token_digest CHAR(64),
  PRIMARY KEY (account_id, device_id)
);

CREATE INDEX IF NOT EXISTS trusted_devices_active_idx
  ON trusted_devices (account_id)
  WHERE revoked_at IS NULL;

CREATE INDEX IF NOT EXISTS trusted_devices_token_digest_idx
  ON trusted_devices (account_id, token_digest)
  WHERE token_digest IS NOT NULL;
