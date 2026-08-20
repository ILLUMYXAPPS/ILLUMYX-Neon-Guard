-- Neon Guard security audit persistence
-- PostgreSQL reference migration. Apply transactionally with the trusted-device migration.

CREATE TABLE IF NOT EXISTS security_audit_events (
  id TEXT PRIMARY KEY,
  account_id TEXT NOT NULL,
  event_type TEXT NOT NULL CHECK (event_type IN (
    'TRUSTED_ACCESS',
    'UNKNOWN_ACCESS',
    'UNTRUSTED_ACCESS',
    'DEVICE_REGISTERED',
    'DEVICE_REVOKED',
    'DEVICE_REPLACED'
  )),
  occurred_at TIMESTAMPTZ NOT NULL,
  provider TEXT,
  device_id TEXT,
  reason TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS security_audit_events_account_time_idx
  ON security_audit_events (account_id, occurred_at DESC);

CREATE INDEX IF NOT EXISTS security_audit_events_untrusted_idx
  ON security_audit_events (account_id, occurred_at DESC)
  WHERE event_type = 'UNTRUSTED_ACCESS';

CREATE UNIQUE INDEX IF NOT EXISTS security_audit_events_id_idx
  ON security_audit_events (id);
