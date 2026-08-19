# Neon Guard Build Roadmap

## Security-first release sequence

### Phase 1: Core security
- [x] Trusted-device storage foundation
- [x] Ownership Control v1 specification
- [x] Cryptographic ownership authorization foundation
- [x] Ownership authorization tests
- [x] CI verification
- [ ] Independent security review
- [ ] Remediate review findings

### Phase 2: Platform integration
- [ ] Complete iOS trusted-device enrollment, revocation, and authentication integration
- [ ] Build Android Keystore trusted-device integration
- [ ] Add platform-specific recovery and device-loss flows

### Phase 3: Server authority
- [ ] Production authentication API
- [ ] Server-side ownership authority
- [ ] Trusted-device token issuance and revocation
- [ ] Session management and replay protection
- [ ] Transactional security datastore
- [ ] Rate limiting and abuse controls

### Phase 4: Monitoring and audit
- [ ] Security event persistence
- [ ] Ownership-change audit trail
- [ ] New-device and suspicious-access alerts
- [ ] Security monitoring dashboard
- [ ] Operational alerting

### Phase 5: Production hardening
- [ ] Secret-management integration
- [ ] TLS and deployment hardening
- [ ] Backups and disaster recovery
- [ ] CI/CD release protections
- [ ] Crash/error monitoring
- [ ] Dependency and supply-chain checks

### Phase 6: Assurance and release
- [ ] Threat-model review
- [ ] Authentication abuse testing
- [ ] Replay/token theft testing
- [ ] Device-loss and recovery testing
- [ ] Independent mobile/API penetration test
- [ ] Privacy/data-flow review
- [ ] Jurisdiction-specific legal/compliance review
- [ ] iOS App Store release preparation
- [ ] Android Play release preparation

## Non-negotiable merge gate

Security-sensitive changes require passing automated tests and CI plus independent security review before merging into `main`.

Neon Guard must not claim universal legal compliance. Compliance claims must be based on an actual data-flow, jurisdiction, product, and legal assessment for each target market.
