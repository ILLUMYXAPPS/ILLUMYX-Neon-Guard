import type { AccessDecision, AccessRequest, AccessPolicy } from './AccessPolicy';
import { BlockedIdentityStore } from './BlockedIdentityStore';

export class AccessGate {
  constructor(
    private readonly store: BlockedIdentityStore,
    private readonly policy: AccessPolicy = { denyKinds: new Set() },
  ) {}

  evaluate(request: AccessRequest): AccessDecision {
    try {
      if (this.policy.denyKinds.has(request.kind)) return { allowed: false, reason: 'blocked_kind' };
      if (this.store.has(request.identifier)) return { allowed: false, reason: 'blocked_identity' };
      return { allowed: true, reason: 'not_blocked' };
    } catch {
      return { allowed: false, reason: 'security_error' };
    }
  }
}
