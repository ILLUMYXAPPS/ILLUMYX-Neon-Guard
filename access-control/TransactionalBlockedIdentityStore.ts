import type { IdentityStore } from './BlockedIdentityStore';

export interface TransactionalBlockedIdentityStore extends IdentityStore {
  transaction<T>(operation: (store: TransactionalBlockedIdentityStore) => Promise<T>): Promise<T>;
}

export class TransactionalStoreAdapter implements TransactionalBlockedIdentityStore {
  constructor(
    private readonly delegate: IdentityStore,
    private readonly transact: <T>(operation: () => Promise<T>) => Promise<T>,
  ) {}

  add(identifier: string): Promise<void> {
    return this.transact(() => Promise.resolve(this.delegate.add(identifier)));
  }

  remove(identifier: string): Promise<void> {
    return this.transact(() => Promise.resolve(this.delegate.remove(identifier)));
  }

  has(identifier: string): Promise<boolean> {
    return Promise.resolve(this.delegate.has(identifier));
  }

  clear(): Promise<void> {
    return this.transact(() => Promise.resolve(this.delegate.clear()));
  }

  transaction<T>(operation: (store: TransactionalBlockedIdentityStore) => Promise<T>): Promise<T> {
    return this.transact(() => operation(this));
  }
}
