import { createHmac } from 'node:crypto';

export function normalizeIdentity(identifier: string): string {
  return identifier.trim().replace(/\s+/g, '').toLowerCase();
}

export function hashIdentity(identifier: string, secret: string): string {
  if (!secret) throw new Error('identity hashing secret is required');
  return createHmac('sha256', secret).update(normalizeIdentity(identifier), 'utf8').digest('hex');
}
