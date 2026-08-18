import { createHash } from 'node:crypto';
export function normalizeIdentity(identifier: string): string { return identifier.trim().replace(/\s+/g, '').toLowerCase(); }
export function hashIdentity(identifier: string): string { return createHash('sha256').update(normalizeIdentity(identifier), 'utf8').digest('hex'); }
