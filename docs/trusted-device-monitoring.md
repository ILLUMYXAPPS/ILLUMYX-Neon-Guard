# Trusted-device monitoring

Neon Guard keeps the trust decision provider-agnostic at its core.

## Device states

- `TRUSTED`: the access event contains a device identifier matching one of the three active trusted-device records.
- `UNTRUSTED`: the provider supplied a device identifier that is not one of the active trusted devices, including a previously registered and revoked device.
- `UNKNOWN`: the event does not contain sufficient device metadata to make a trustworthy device match.

## Security boundaries

The monitoring layer must not persist passwords, MFA secrets, recovery codes, or other authentication secrets. Provider adapters are responsible for translating provider-specific security events into the normalized access-event model.

A provider may expose different device/session metadata and different response capabilities. Neon Guard must not claim it can block or revoke a provider session unless that provider explicitly exposes the required API.
