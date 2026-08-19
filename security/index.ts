export { authorizeAuthentication } from './AuthenticationGuard';
export { authorizeOwnershipChange, CANONICAL_OWNER } from './OwnershipControl';
export { issueTrustedDeviceToken, tokenDigest, validateTrustedDeviceToken } from './TrustedDeviceToken';
export { InMemorySecurityLogger } from './SecurityLogger';
export type { OwnershipAuthorization, OwnershipChangeDecision, OwnershipState } from './OwnershipControl';
export type { TrustedDeviceTokenRecord, TrustedDeviceTokenStore, TokenValidationResult } from './TrustedDeviceToken';
export type { SecurityLogger } from './SecurityLogger';
export type { SecurityEvent, SecurityEventType } from './SecurityEvent';
