import type { AccessDecision, AccessRequest, AccessPolicy } from './AccessPolicy';
import type { IdentityStore } from './BlockedIdentityStore';

export class AccessGate {
  constructor(
    private readonly store: IdentityStore,
    private readonly policy: AccessPolicy = { denyKinds: new Set() },
  ) {}

  evaluate(request: AccessRequest): AccessDecision {
    try {
      if (this.policy.denyKinds.has(request.kind)) return { allowed: false, reason: 'blocked_kind' };
      const result = this.store.has(request.identifier);
      if (result instanceof Promise) return { allowed: false, reason: 'security_error' };
      if (result) return { allowed: false, reason: 'blocked_identity' };
      return { allowed: true, reason: 'not_blocked' };
    } catch {
      return { allowed: false, reason: 'security_error' };
    }
  }

  async evaluateAsync(request: AccessRequest): Promise<AccessDecision> {
    try {
      if (this.policy.denyKinds.has(request.kind)) return { allowed: false, reason: 'blocked_kind' };
      if (await this.store.has(request.identifier)) return { allowed: false, reason: 'blocked_identity' };
      return { allowed: true, reason: 'not_blocked' };
    } catch {
      return { allowed: false, reason: 'security_error' };
    }
  }
}
