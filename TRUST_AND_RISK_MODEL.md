# Trust and Risk Model for Trusted Issuer Registry

## Overview
This document outlines the trust model, threat considerations, and mitigation strategies used in the trusted-issuer-registry. It is intended to provide transparency and build confidence for integrators, fintech organizations, and relying parties using this registry as a source of authoritative issuers.

## 1. Trust Model
- We aggregate and validate trusted issuers recognized by authoritative trust lists (AAMVA DTS VICAL, Universal Verify, etc.).
- Each issuer is associated with either a W3C Decentralized Identifier (DID) or X.509 certificates used to validate digital credentials
  - Currently only issuers using certificates are available in the registry. Schema subject to change once issuers using DID are added
- Trust anchors (issuer certificates) are versioned and cryptographically verifiable.
- Inclusion in the registry follows defined vetting criteria (see `TRUST_POLICY.md`).

## 2. Data Integrity and Authenticity
- All data is signed using a private EC key on the NIST P-256 (prime256v1) curve.
  - This private key is stored as a GitHub secret
  - Our key rotation policy is to update with each minor version release, or in the event of a compromised private key
  - The public key is stored in the root of the repo as public_signing_key.pem
- Registry state is immutable and publicly auditable via GitHub's commit history and pull requests, enabling transparent review of issuer changes over time.
- We do not issue credentials, we only aggregate and validate issuer metadata.

## 3. Threat Model

This section outlines specific threat vectors relevant to the Trusted Issuer Registry and the mitigation strategies implemented to address each.

### 3.1 Tampering with Published Registry Data

**Risk:** Unauthorized inclusion, removal, or modification of issuers in the __registry__ could compromise downstream trust validation.

**Mitigations:**
- All issuer metadata is signed using a project-managed EC private key (NIST P-256).
- Git-based change control with public audit trail (pull requests and commit history).
- Restricted access to merge into protected main branch.

### 3.2 Tampering with Upstream Trust List Sources

**Risk:** If a trust list publishes an altered or malicious version of the list, or if an attacker spoofs or tampers with it in transit, the registry may ingest untrustworthy issuers, compromising the integrity of the aggregated registry data.

**Mitigations:**
- All imported trust list data is verified using the list’s own published signing keys, certificates, or checksums where applicable.
- Registry changes derived from trust lists are subject to the same maintainer-reviewed pull request process that all repository changes are, so unexpected changes may be caught during review.

### 3.3 Man-in-the-Middle (MITM) Attacks

**Risk:** An attacker could intercept or alter registry data in transit to consumers.

**Mitigations:**
- All registry data is cryptographically signed; consumers must verify signatures.
- Public key for signature validation is published and version-controlled.
- Trusted endpoints are served via jsDelivr CDN over HTTPS.

### 3.4 Expired or Compromised Certificates

**Risk:** If issuer certificates are expired or compromised, relying parties may unknowingly trust invalid or malicious identities.

**Mitigations:**
- Continuous monitoring of certificate validity and expiration.
- Certificate lifecycle and removal policies defined in `TRUST_POLICY.md`.
- Cross-verification against authoritative trust lists for updated certificates.

### 3.5 Insider Threat

**Risk:** Maintainers or collaborators with elevated privileges could abuse access to insert untrusted issuers or weaken validation policies.

**Mitigations:**
- Write access to protected branches and signing infrastructure is limited to maintainer(s).
- Full auditability is enforced via GitHub pull requests and commit history.

### 3.6 Denial of Service (DoS)

**Risk:** Malicious actors may attempt to overload registry access points, impacting availability for integrators or verifiers.

**Mitigations:**
- Global CDN distribution via jsDelivr, which offers caching and load balancing.
- Integrators are encouraged to mirror and pin registry snapshots locally for resilience.


## 4. Governance and Change Control
- All changes to the trust list require a pull request review by the maintainer(s).
- At this time, we encourage large trusted organizations to volunteer a representative to help in the auditing of this registry.

## 5. Disclaimers and Limitations
- This registry is provided as-is with no warranty.
- As an aggregate of trust lists, we recommend consumers perform their own due diligence and apply local policy before relying on any trust list or issuer provided in this registry.

## 6. Contact and Reporting
To report security concerns, please email kale@universalverify.com

