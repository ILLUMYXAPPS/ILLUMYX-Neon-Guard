# iOS integration

Neon Guard's iOS layer is intentionally a thin client boundary.

## Security boundary

The iOS application does **not** contain the blocklist, HMAC secret, or authorization policy. It sends an authorized request to the ILLUMYX-controlled service and consumes the resulting `ALLOW` or `DENY` decision.

The client treats non-2xx responses as failures rather than granting access locally.

## Expected endpoint contract

`POST <configured endpoint>`

Request:

```json
{"credential":"..."}
```

Response:

```json
{"decision":"ALLOW"}
```

or

```json
{"decision":"DENY"}
```

The actual production endpoint, authentication mechanism, certificate/pinning strategy, and credential format must be defined by the authorized backend implementation before release. No secrets belong in this repository or in the iOS binary.
