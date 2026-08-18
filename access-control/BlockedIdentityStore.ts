import { hashIdentity } from './IdentityHasher';
export class BlockedIdentityStore {
  private readonly blocked = new Set<string>();
  add(identifier: string): void { this.blocked.add(hashIdentity(identifier)); }
  remove(identifier: string): void { this.blocked.delete(hashIdentity(identifier)); }
  has(identifier: string): boolean { return this.blocked.has(hashIdentity(identifier)); }
  clear(): void { this.blocked.clear(); }
}
