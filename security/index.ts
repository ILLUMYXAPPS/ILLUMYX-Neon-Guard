export { authorizeAuthentication } from './AuthenticationGuard';
export { authorizeOwnershipChange, CANONICAL_OWNER } from './OwnershipControl';
export { InMemorySecurityLogger } from './SecurityLogger';
export type { OwnershipAuthorization, OwnershipChangeDecision, OwnershipState } from './OwnershipControl';
export type { SecurityLogger } from './SecurityLogger';
export type { SecurityEvent, SecurityEventType } from './SecurityEvent';
