import { hashIdentity } from './IdentityHasher';

export class BlockedIdentityStore {
  private readonly blocked = new Set<string>();

  constructor(private readonly secret: string) {
    if (!secret) throw new Error('identity hashing secret is required');
  }

  add(identifier: string): void { this.blocked.add(hashIdentity(identifier, this.secret)); }
  remove(identifier: string): void { this.blocked.delete(hashIdentity(identifier, this.secret)); }
  has(identifier: string): boolean { return this.blocked.has(hashIdentity(identifier, this.secret)); }
  clear(): void { this.blocked.clear(); }
}
