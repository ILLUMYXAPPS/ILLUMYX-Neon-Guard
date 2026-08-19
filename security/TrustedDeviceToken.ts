import { createHash, randomUUID, timingSafeEqual } from 'node:crypto';

export interface TrustedDeviceTokenRecord {
  tokenId: string;
  deviceId: string;
  issuedAt: number;
  expiresAt: number;
  revokedAt?: number;
}

export interface TrustedDeviceTokenStore {
  get(tokenId: string): TrustedDeviceTokenRecord | undefined;
  put(record: TrustedDeviceTokenRecord): void;
  revoke(tokenId: string, revokedAt: number): void;
  markUsed?(tokenId: string): void;
  wasUsed?(tokenId: string): boolean;
}

export interface TokenValidationResult {
  valid: boolean;
  reason: 'valid' | 'malformed' | 'unknown' | 'expired' | 'revoked' | 'replayed';
  record?: TrustedDeviceTokenRecord;
}

export function issueTrustedDeviceToken(
  store: TrustedDeviceTokenStore,
  deviceId: string,
  now = Date.now(),
  ttlMs = 24 * 60 * 60 * 1000,
): string {
  if (!deviceId || ttlMs <= 0) throw new Error('invalid_token_parameters');
  const tokenId = randomUUID();
  const record: TrustedDeviceTokenRecord = { tokenId, deviceId, issuedAt: now, expiresAt: now + ttlMs };
  store.put(record);
  return tokenId;
}

export function tokenDigest(tokenId: string): string {
  return createHash('sha256').update(tokenId, 'utf8').digest('hex');
}

function constantTimeTokenIdEqual(a: string, b: string): boolean {
  const left = Buffer.from(a, 'utf8');
  const right = Buffer.from(b, 'utf8');
  if (left.length !== right.length) return false;
  return timingSafeEqual(left, right);
}

export function validateTrustedDeviceToken(
  store: TrustedDeviceTokenStore,
  tokenId: string,
  now = Date.now(),
  consume = true,
): TokenValidationResult {
  if (!tokenId || tokenId.length > 256) return { valid: false, reason: 'malformed' };
  const record = store.get(tokenId);
  if (!record) return { valid: false, reason: 'unknown' };
  if (!constantTimeTokenIdEqual(record.tokenId, tokenId)) return { valid: false, reason: 'unknown' };
  if (record.revokedAt !== undefined) return { valid: false, reason: 'revoked', record };
  if (now >= record.expiresAt) return { valid: false, reason: 'expired', record };
  if (store.wasUsed?.(tokenId)) return { valid: false, reason: 'replayed', record };
  if (consume) store.markUsed?.(tokenId);
  return { valid: true, reason: 'valid', record };
}
