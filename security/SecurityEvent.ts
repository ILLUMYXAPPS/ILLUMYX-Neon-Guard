export type SecurityEventType = 'access_allowed' | 'access_denied';
export interface SecurityEvent { type: SecurityEventType; identityKind: string; reason: string; timestamp: string; }
