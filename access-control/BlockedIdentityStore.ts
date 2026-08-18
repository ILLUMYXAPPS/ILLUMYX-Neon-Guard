import { promises as fs } from 'node:fs';
import { dirname } from 'node:path';
import { hashIdentity } from './IdentityHasher';

export interface IdentityStore {
  add(identifier: string): void | Promise<void>;
  remove(identifier: string): void | Promise<void>;
  has(identifier: string): boolean | Promise<boolean>;
  clear(): void | Promise<void>;
}

export class BlockedIdentityStore implements IdentityStore {
  private readonly blocked = new Set<string>();

  constructor(private readonly secret: string) {
    if (!secret) throw new Error('identity hashing secret is required');
  }

  add(identifier: string): void { this.blocked.add(hashIdentity(identifier, this.secret)); }
  remove(identifier: string): void { this.blocked.delete(hashIdentity(identifier, this.secret)); }
  has(identifier: string): boolean { return this.blocked.has(hashIdentity(identifier, this.secret)); }
  clear(): void { this.blocked.clear(); }
}

export class PersistentBlockedIdentityStore implements IdentityStore {
  private blocked = new Set<string>();
  private initialized = false;

  constructor(
    private readonly filePath: string,
    private readonly secret: string,
  ) {
    if (!secret) throw new Error('identity hashing secret is required');
  }

  async init(): Promise<void> {
    if (this.initialized) return;
    try {
      const raw = await fs.readFile(this.filePath, 'utf8');
      const values: unknown = JSON.parse(raw);
      if (!Array.isArray(values) || !values.every((value) => typeof value === 'string')) {
        throw new Error('invalid blocked identity store');
      }
      this.blocked = new Set(values);
    } catch (error: unknown) {
      const code = error && typeof error === 'object' && 'code' in error ? error.code : undefined;
      if (code !== 'ENOENT') throw error;
      await this.persist();
    }
    this.initialized = true;
  }

  async add(identifier: string): Promise<void> {
    await this.init();
    this.blocked.add(hashIdentity(identifier, this.secret));
    await this.persist();
  }

  async remove(identifier: string): Promise<void> {
    await this.init();
    this.blocked.delete(hashIdentity(identifier, this.secret));
    await this.persist();
  }

  async has(identifier: string): Promise<boolean> {
    await this.init();
    return this.blocked.has(hashIdentity(identifier, this.secret));
  }

  async clear(): Promise<void> {
    await this.init();
    this.blocked.clear();
    await this.persist();
  }

  private async persist(): Promise<void> {
    await fs.mkdir(dirname(this.filePath), { recursive: true });
    const tempPath = `${this.filePath}.tmp`;
    await fs.writeFile(tempPath, `${JSON.stringify([...this.blocked])}\n`, { encoding: 'utf8', mode: 0o600 });
    await fs.rename(tempPath, this.filePath);
  }
}
