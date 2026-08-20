import { AccessEvent } from './TrustedDeviceRegistry';
import { ProviderAccessEvent } from './AccessEventMonitor';

export interface NormalizedProviderAccessEvent extends AccessEvent {
  eventId: string;
}

export interface ProviderAdapter {
  readonly provider: string;
  normalize(event: ProviderAccessEvent): NormalizedProviderAccessEvent;
}
