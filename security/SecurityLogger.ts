import type { SecurityEvent } from './SecurityEvent';
export interface SecurityLogger { record(event: SecurityEvent): void; }
export class InMemorySecurityLogger implements SecurityLogger {
  readonly events: SecurityEvent[] = [];
  record(event: SecurityEvent): void { this.events.push({ ...event }); }
}
