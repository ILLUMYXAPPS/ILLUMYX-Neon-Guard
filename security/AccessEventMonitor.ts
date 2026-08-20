import { AccessEvent, DeviceClassification, TrustedDeviceRegistry } from './TrustedDeviceRegistry';
import type { SecurityAuditEvent, SecurityAuditStore } from './SecurityAuditStore';
import type { SecurityAlertDispatcher } from './SecurityAlertDispatcher';

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

  constructor(
    private readonly registry: TrustedDeviceRegistry,
    private readonly auditStore?: SecurityAuditStore,
    private readonly alertDispatcher?: SecurityAlertDispatcher,
  ) {}

  ingest(event: AccessEvent & { eventId: string }): { duplicate: boolean; audit?: AuditEvent; alert?: AccessAlert } {
    if (this.seen.has(event.eventId)) return { duplicate: true };
    this.seen.add(event.eventId);

    const classification = this.registry.classifyAccess(event);
    const audit: AuditEvent = { ...event, classification };
    this.auditTrail.push(audit);

    const auditType = classification.state === 'TRUSTED'
      ? 'TRUSTED_ACCESS'
      : classification.state === 'UNKNOWN' ? 'UNKNOWN_ACCESS' : 'UNTRUSTED_ACCESS';
    const securityEvent: SecurityAuditEvent = {
      id: event.eventId,
      accountId: event.accountId,
      type: auditType,
      timestamp: event.timestamp,
      provider: event.provider,
      deviceId: event.deviceId,
      reason: classification.reason,
    };

    this.auditStore?.append(securityEvent);

    if (classification.state === 'UNTRUSTED') {
      const alert: AccessAlert = {
        type: 'UNTRUSTED_ACCESS',
        accountId: event.accountId,
        provider: event.provider,
        timestamp: event.timestamp,
        classification,
      };
      this.alerts.push(alert);
      this.alertDispatcher?.dispatch(securityEvent);
      return { duplicate: false, audit, alert };
    }

    return { duplicate: false, audit };
  }

  getAuditTrail(): readonly AuditEvent[] { return this.auditTrail; }
  getAlerts(): readonly AccessAlert[] { return this.alerts; }
}
