# Unauthorised login monitoring

`UnauthorisedLoginMonitor` checks each authentication attempt against the recognised-device registry.

- Recognised device: login is allowed and no alert is emitted.
- Unrecognised device: login is rejected by the monitor and an `unauthorised_login` alert is emitted.
- Alerts may include device, platform, IP address and coarse location supplied by the host application.
- Do not send passwords, access tokens, private keys, or other credentials to the monitor.

The host application should connect `onUnauthorisedLogin()` to its approved notification channel and persist security events in its controlled backend/audit store.
