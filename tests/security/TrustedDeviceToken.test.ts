import { describe, expect, it } from 'vitest';
import { issueTrustedDeviceToken, validateTrustedDeviceToken, type TrustedDeviceTokenRecord, type TrustedDeviceTokenStore } from '../../security/TrustedDeviceToken';

class TestStore implements TrustedDeviceTokenStore {
  private records = new Map<string, TrustedDeviceTokenRecord>();
  private used = new Set<string>();
  get(tokenId: string) { return this.records.get(tokenId); }
  put(record: TrustedDeviceTokenRecord) { this.records.set(record.tokenId, record); }
  revoke(tokenId: string, revokedAt: number) { const record = this.records.get(tokenId); if (record) this.records.set(tokenId, { ...record, revokedAt }); }
  markUsed(tokenId: string) { this.used.add(tokenId); }
  wasUsed(tokenId: string) { return this.used.has(tokenId); }
}

describe('Trusted device token lifecycle', () => {
  it('issues and validates a token once', () => {
    const store = new TestStore();
    const token = issueTrustedDeviceToken(store, 'device-1', 1000, 5000);
    expect(validateTrustedDeviceToken(store, token, 2000)).toMatchObject({ valid: true, reason: 'valid', record: { deviceId: 'device-1' } });
    expect(validateTrustedDeviceToken(store, token, 2001)).toMatchObject({ valid: false, reason: 'replayed' });
  });

  it('rejects expired tokens', () => {
    const store = new TestStore();
    const token = issueTrustedDeviceToken(store, 'device-1', 1000, 100);
    expect(validateTrustedDeviceToken(store, token, 1100)).toMatchObject({ valid: false, reason: 'expired' });
  });

  it('rejects revoked tokens', () => {
    const store = new TestStore();
    const token = issueTrustedDeviceToken(store, 'device-1', 1000, 5000);
    store.revoke(token, 1500);
    expect(validateTrustedDeviceToken(store, token, 1600)).toMatchObject({ valid: false, reason: 'revoked' });
  });

  it('rejects malformed and unknown tokens', () => {
    const store = new TestStore();
    expect(validateTrustedDeviceToken(store, '')).toEqual({ valid: false, reason: 'malformed' });
    expect(validateTrustedDeviceToken(store, 'not-issued')).toEqual({ valid: false, reason: 'unknown' });
  });
});
