export type IdentityKind = 'phone' | 'account' | 'device' | 'session';
export interface AccessRequest { kind: IdentityKind; identifier: string; }
export interface AccessPolicy { denyKinds: ReadonlySet<IdentityKind>; }
export type AccessDecision =
  | { allowed: true; reason: 'not_blocked' }
  | { allowed: false; reason: 'blocked_identity' | 'blocked_kind' };
