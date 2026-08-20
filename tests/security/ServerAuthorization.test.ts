import { describe, expect, it } from 'vitest';
import { authorizeServerRequest, type AuthorizationAuditSink } from '../../security/ServerAuthorization';
import { issueTrustedDeviceToken, type TrustedDeviceTokenRecord, type TrustedDeviceTokenStore } from '../../security/TrustedDeviceToken';

class Store implements TrustedDeviceTokenStore {
  records = new Map<string, TrustedDeviceTokenRecord>();
  used = new Set<string>();
  get(id: string) { return this.records.get(id); }
  put(record: TrustedDeviceTokenRecord) { this.records.set(record.tokenId, record); }
  revoke(id: string, at: number) { const r = this.records.get(id); if (r) this.records.set(id, { ...r, revokedAt: at }); }
  markUsed(id: string) { this.used.add(id); }
  wasUsed(id: string) { return this.used.has(id); }
}

class Audit implements AuthorizationAuditSink {
  events: Array<{ outcome: 'allowed' | 'denied'; reason: string }> = [];
  record(event: { outcome: 'allowed' | 'denied'; reason: string }) { this.events.push(event); }
}

describe('Server authorization boundary', () => {
  it('allows a request from the device bound to a valid token', () => {
    const store = new Store();
    const audit = new Audit();
    const token = issueTrustedDeviceToken(store, 'device-1', 1000, 5000);
    expect(authorizeServerRequest({ tokenId: token, deviceId: 'device-1', resource: 'account', action: 'read' }, store, audit, 2000)).toEqual({ allowed: true, reason: 'authorized' });
  });

  it('rejects a token presented by another device', () => {
    const store = new Store();
    const audit = new Audit();
    const token = issueTrustedDeviceToken(store, 'device-1', 1000, 5000);
    expect(authorizeServerRequest({ tokenId: token, deviceId: 'device-2', resource: 'account', action: 'read' }, store, audit, 2000)).toEqual({ allowed: false, reason: 'device_mismatch' });
  });

  it('rejects expired and revoked tokens', () => {
    const store = new Store();
    const audit = new Audit();
    const expired = issueTrustedDeviceToken(store, 'device-1', 1000, 100);
    expect(authorizeServerRequest({ tokenId: expired, deviceId: 'device-1', resource: 'account', action: 'read' }, store, audit, 1100)).toEqual({ allowed: false, reason: 'expired_token' });
    const revoked = issueTrustedDeviceToken(store, 'device-1', 1000, 5000);
    store.revoke(revoked, 1500);
    expect(authorizeServerRequest({ tokenId: revoked, deviceId: 'device-1', resource: 'account', action: 'read' }, store, audit, 1600)).toEqual({ allowed: false, reason: 'revoked_token' });
  });

  it('consumes an authorization token and rejects replay', () => {
    const store = new Store();
    const audit = new Audit();
    const token = issueTrustedDeviceToken(store, 'device-1', 1000, 5000);
    const request = { tokenId: token, deviceId: 'device-1', resource: 'account', action: 'read' };

    expect(authorizeServerRequest(request, store, audit, 2000)).toEqual({ allowed: true, reason: 'authorized' });
    expect(authorizeServerRequest(request, store, audit, 2001)).toEqual({ allowed: false, reason: 'replayed_token' });
  });

  it('audits authorization outcomes', () => {
    const store = new Store();
    const audit = new Audit();
    authorizeServerRequest({ tokenId: '', deviceId: 'device-1', resource: 'account', action: 'read' }, store, audit, 1000);
    expect(audit.events).toContainEqual(expect.objectContaining({ outcome: 'denied', reason: 'invalid_request' }));
  });
});
