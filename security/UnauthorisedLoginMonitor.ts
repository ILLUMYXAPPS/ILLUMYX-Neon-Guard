export interface LoginAttempt {
  identityKind: string;
  deviceId: string;
  deviceLabel?: string;
  platform?: string;
  ipAddress?: string;
  location?: string;
  timestamp?: string;
}

export interface UnauthorisedLoginAlert {
  type: 'unauthorised_login';
  identityKind: string;
  deviceId: string;
  deviceLabel?: string;
  platform?: string;
  ipAddress?: string;
  location?: string;
  timestamp: string;
  reason: 'unrecognised_device';
}

export type LoginAlertHandler = (alert: UnauthorisedLoginAlert) => void;

/**
 * Checks login attempts against the application's recognised-device registry.
 * Device identifiers should be stable, non-secret identifiers. Do not pass
 * passwords, access tokens, or other credentials into this monitor.
 */
export class UnauthorisedLoginMonitor {
  private readonly recognisedDevices = new Map<string, string>();
  private readonly alertHandlers = new Set<LoginAlertHandler>();

  registerRecognisedDevice(deviceId: string, label: string): void {
    if (!deviceId.trim()) throw new Error('deviceId is required');
    this.recognisedDevices.set(deviceId, label);
  }

  removeRecognisedDevice(deviceId: string): void {
    this.recognisedDevices.delete(deviceId);
  }

  isRecognisedDevice(deviceId: string): boolean {
    return this.recognisedDevices.has(deviceId);
  }

  onUnauthorisedLogin(handler: LoginAlertHandler): () => void {
    this.alertHandlers.add(handler);
    return () => this.alertHandlers.delete(handler);
  }

  evaluate(attempt: LoginAttempt): boolean {
    if (this.isRecognisedDevice(attempt.deviceId)) return true;

    const alert: UnauthorisedLoginAlert = {
      type: 'unauthorised_login',
      identityKind: attempt.identityKind,
      deviceId: attempt.deviceId,
      ...(attempt.deviceLabel ? { deviceLabel: attempt.deviceLabel } : {}),
      ...(attempt.platform ? { platform: attempt.platform } : {}),
      ...(attempt.ipAddress ? { ipAddress: attempt.ipAddress } : {}),
      ...(attempt.location ? { location: attempt.location } : {}),
      timestamp: attempt.timestamp ?? new Date().toISOString(),
      reason: 'unrecognised_device',
    };

    for (const handler of this.alertHandlers) handler({ ...alert });
    return false;
  }
}
