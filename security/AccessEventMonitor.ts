import { AccessEvent, DeviceClassification, TrustedDeviceRegistry } from './TrustedDeviceRegistry';

export interface AccessAlert {
  type: 'UNTRUSTED_ACCESS';
  accountId: string;
  provider: string;
  timestamp: number;
  classification: DeviceClassification;
}

export interface AuditEvent extends AccessEvent {
  classification: DeviceClassification;
}

export interface ProviderAccessEvent {
  accountId: string;
  provider: string;
  eventId: string;
  timestamp: number;
  deviceId?: string;
  platform?: string;
}

export interface ProviderAdapter {
  normalize(event: ProviderAccessEvent): AccessEvent & { eventId: string };
}

export class AccessEventMonitor {
  private readonly seen = new Set<string>();
  private readonly auditTrail: AuditEvent[] = [];
  private readonly alerts: AccessAlert[] = [];

  constructor(private readonly registry: TrustedDeviceRegistry) {}

  ingest(event: AccessEvent & { eventId: string }): { duplicate: boolean; audit?: AuditEvent; alert?: AccessAlert } {
    if (this.seen.has(event.eventId)) return { duplicate: true };
    this.seen.add(event.eventId);

    const classification = this.registry.classifyAccess(event);
    const audit: AuditEvent = { ...event, classification };
    this.auditTrail.push(audit);

    if (classification.state === 'UNTRUSTED') {
      const alert: AccessAlert = {
        type: 'UNTRUSTED_ACCESS',
        accountId: event.accountId,
        provider: event.provider,
        timestamp: event.timestamp,
        classification,
      };
      this.alerts.push(alert);
      return { duplicate: false, audit, alert };
    }

    return { duplicate: false, audit };
  }

  getAuditTrail(): readonly AuditEvent[] { return this.auditTrail; }
  getAlerts(): readonly AccessAlert[] { return this.alerts; }
}
