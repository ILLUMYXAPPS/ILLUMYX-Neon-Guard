import { createVerify } from 'node:crypto';
import type { SecurityLogger } from './SecurityLogger';

export const CANONICAL_OWNER = 'Aaron Stephen Paszek';

export interface OwnershipAuthorization {
  ownerId: string;
  payload: string;
  signature: string;
  publicKeyPem: string;
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

function verifySignature(auth: OwnershipAuthorization): boolean {
  try {
    const verifier = createVerify('SHA256');
    verifier.update(auth.payload, 'utf8');
    verifier.end();
    return verifier.verify(auth.publicKeyPem, auth.signature, 'base64');
  } catch {
    return false;
  }
}

export function authorizeOwnershipChange(
  current: OwnershipState,
  requested: OwnershipState,
  authorization: OwnershipAuthorization,
  logger: SecurityLogger,
): OwnershipChangeDecision {
  if (!authorization.payload || !authorization.signature || !authorization.publicKeyPem) {
    const decision = { allowed: false, reason: 'invalid_payload' as const, state: current };
    logger.record({ type: 'access_denied', identityKind: 'ownership', reason: decision.reason, timestamp: new Date().toISOString() });
    return decision;
  }

  if (authorization.ownerId !== current.ownerId || requested.ownerId !== current.ownerId) {
    const decision = { allowed: false, reason: 'owner_mismatch' as const, state: current };
    logger.record({ type: 'access_denied', identityKind: 'ownership', reason: decision.reason, timestamp: new Date().toISOString() });
    return decision;
  }

  if (!verifySignature(authorization)) {
    const decision = { allowed: false, reason: 'invalid_signature' as const, state: current };
    logger.record({ type: 'access_denied', identityKind: 'ownership', reason: decision.reason, timestamp: new Date().toISOString() });
    return decision;
  }

  const nextState = { ...requested, version: current.version + 1 };
  logger.record({ type: 'access_allowed', identityKind: 'ownership', reason: 'authorized_owner', timestamp: new Date().toISOString() });
  return { allowed: true, reason: 'authorized_owner', state: nextState };
}
