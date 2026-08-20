import { createVerify } from 'node:crypto';
import type { SecurityLogger } from './SecurityLogger';

export const CANONICAL_OWNER = 'Aaron Stephen Paszek';

export interface OwnershipAuthorization {
  ownerId: string;
  payload: string;
  signature: string;
}

export interface OwnershipState {
  ownerId: string;
  ownerDisplayName: string;
  version: number;
}

export interface OwnershipChangeDecision {
  allowed: boolean;
  reason: 'authorized_owner' | 'invalid_signature' | 'owner_mismatch' | 'invalid_payload';
  state: OwnershipState;
}

export interface OwnerKeyRegistry {
  getPublicKeyPem(ownerId: string): string | undefined;
}

function verifySignature(payload: string, signature: string, publicKeyPem: string): boolean {
  try {
    const verifier = createVerify('SHA256');
    verifier.update(payload, 'utf8');
    verifier.end();
    return verifier.verify(publicKeyPem, signature, 'base64');
  } catch {
    return false;
  }
}

export function authorizeOwnershipChange(
  current: OwnershipState,
  requested: OwnershipState,
  authorization: OwnershipAuthorization,
  keyRegistry: OwnerKeyRegistry,
  logger: SecurityLogger,
): OwnershipChangeDecision {
  if (!authorization.payload || !authorization.signature) {
    const decision = { allowed: false, reason: 'invalid_payload' as const, state: current };
    logger.record({ type: 'access_denied', identityKind: 'ownership', reason: decision.reason, timestamp: new Date().toISOString() });
    return decision;
  }

  if (authorization.ownerId !== current.ownerId || requested.ownerId !== current.ownerId) {
    const decision = { allowed: false, reason: 'owner_mismatch' as const, state: current };
    logger.record({ type: 'access_denied', identityKind: 'ownership', reason: decision.reason, timestamp: new Date().toISOString() });
    return decision;
  }

  const expectedPayload = JSON.stringify({ ownerId: current.ownerId, version: current.version, requested });
  if (authorization.payload !== expectedPayload) {
    const decision = { allowed: false, reason: 'invalid_payload' as const, state: current };
    logger.record({ type: 'access_denied', identityKind: 'ownership', reason: decision.reason, timestamp: new Date().toISOString() });
    return decision;
  }

  const publicKeyPem = keyRegistry.getPublicKeyPem(current.ownerId);
  if (!publicKeyPem || !verifySignature(expectedPayload, authorization.signature, publicKeyPem)) {
    const decision = { allowed: false, reason: 'invalid_signature' as const, state: current };
    logger.record({ type: 'access_denied', identityKind: 'ownership', reason: decision.reason, timestamp: new Date().toISOString() });
    return decision;
  }

  const nextState = { ...requested, version: current.version + 1 };
  logger.record({ type: 'access_allowed', identityKind: 'ownership', reason: 'authorized_owner', timestamp: new Date().toISOString() });
  return { allowed: true, reason: 'authorized_owner', state: nextState };
}
