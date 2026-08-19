import type { TrustedDeviceTokenStore } from './TrustedDeviceToken';
import { validateTrustedDeviceToken } from './TrustedDeviceToken';

export interface ServerAuthorizationRequest {
  tokenId: string;
  deviceId: string;
  resource: string;
  action: string;
}

export interface ServerAuthorizationDecision {
  allowed: boolean;
  reason: 'authorized' | 'unknown_token' | 'expired_token' | 'revoked_token' | 'replayed_token' | 'device_mismatch' | 'invalid_request';
}

export interface AuthorizationAuditSink {
  record(event: { outcome: 'allowed' | 'denied'; reason: ServerAuthorizationDecision['reason']; deviceId?: string; resource?: string; action?: string; timestamp: string }): void;
}

export function authorizeServerRequest(
  request: ServerAuthorizationRequest,
  tokenStore: TrustedDeviceTokenStore,
  audit: AuthorizationAuditSink,
  now = Date.now(),
): ServerAuthorizationDecision {
  if (!request.tokenId || !request.deviceId || !request.resource || !request.action) {
    const decision: ServerAuthorizationDecision = { allowed: false, reason: 'invalid_request' };
    audit.record({ outcome: 'denied', reason: decision.reason, timestamp: new Date(now).toISOString() });
    return decision;
  }

  const token = validateTrustedDeviceToken(tokenStore, request.tokenId, now, false);
  if (!token.valid || !token.record) {
    const reason: ServerAuthorizationDecision['reason'] = token.reason === 'expired' ? 'expired_token' : token.reason === 'revoked' ? 'revoked_token' : token.reason === 'replayed' ? 'replayed_token' : 'unknown_token';
    const decision: ServerAuthorizationDecision = { allowed: false, reason };
    audit.record({ outcome: 'denied', reason, deviceId: request.deviceId, resource: request.resource, action: request.action, timestamp: new Date(now).toISOString() });
    return decision;
  }

  if (token.record.deviceId !== request.deviceId) {
    const decision: ServerAuthorizationDecision = { allowed: false, reason: 'device_mismatch' };
    audit.record({ outcome: 'denied', reason: decision.reason, deviceId: request.deviceId, resource: request.resource, action: request.action, timestamp: new Date(now).toISOString() });
    return decision;
  }

  const decision: ServerAuthorizationDecision = { allowed: true, reason: 'authorized' };
  audit.record({ outcome: 'allowed', reason: decision.reason, deviceId: request.deviceId, resource: request.resource, action: request.action, timestamp: new Date(now).toISOString() });
  return decision;
}
