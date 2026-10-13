# Changelog

Notable library, schema, and registry changes are documented here. Routine issuer
refreshes are summarized per published release; detailed issuer changes are
available in the linked release diffs and Git history.

This changelog starts with the 0.2.x release line. Earlier releases have not been
backfilled.

## [Unreleased]

### Removed

- Retired the daily issuer-update workflow for the 0.1.x registry after its
  end-of-life date on 2026-10-09.

## [0.2.2] - 2026-10-08

### Fixed

- Moved `cbor2` from runtime dependencies to development dependencies. CBOR is
  needed only by trust-list import tooling and tests, so consumers no longer
  install an unused dependency whose newer releases require Node 22.
- Pinned the development dependency to `cbor2@2.3.0` to keep import tooling
  compatible with Node 20.

## [0.2.1] - 2026-10-06

First supported release of the 0.2.x schema and expanded JavaScript library.

### Added

- `Registry.resolveCertificateTrust()` for PEM strings and parsed PKIjs
  certificates, checking signatures, issuer names, validity dates, and optional
  trust-list, trust-scope, and revocation requirements.
- User-provided trusted issuer certificates as PEM strings or objects with
  metadata overrides, usable independently of the registry or alongside it.
- Issuer details and all issuer certificates in trust results, with per-certificate
  trust and revocation status and machine-readable `UntrustedReason` codes.
- Optional CRL checks through `skip`, `best_effort`, and `required` modes.
  Revocation checking defaults to `skip`.
- Named `TrustList`, `TrustScope`, `RevocationCheckMode`, and `UntrustedReason`
  constants, plus `parsePemCertificate()`, `certificateToPem()`, and
  `verifyCertificateSignature()` utility exports.
- TypeScript declarations for the package and all four build variants, supporting
  strict NodeNext and browser/Bundler consumers.
- Shared in-flight requests and caching for issuers, deprecation notices, and
  CRLs, with a 1,024-entry LRU limit and a configurable 10-second request timeout.

### Changed

- Replaced the default `TrustedIssuerRegistry` export with the named `Registry`
  export. Migrate to `import { Registry } from 'trusted-issuer-registry'`.
- Added required issuer-level `trust_scopes`, supporting `government_issued_id`
  and `document_signing`. Empty arrays are allowed.
- Simplified `entity_metadata` to optional `country` and `region` fields, removed
  entity-specific required fields, and disallowed additional metadata properties.
- `getIssuerFromX509AKI()` now merges registry and user-provided issuers. User
  metadata takes precedence, scopes and certificates are combined, and
  user-provided certificates appear first. Merged issuers and trust results omit
  the registry signature, which is verified before merging.
- `resolveCertificateTrust()` uses only user-provided issuers by default. Pass
  `trustLists` explicitly to query the registry; omit `trustScope` to skip scope
  checking.
- `verifySignatureWithPem()` accepts signature options. RSA requires explicit
  algorithm and hash options; RSA-PSS also requires a salt length. ECDSA defaults
  its hash from the certificate's curve and supports explicit overrides.
- UV imports use upstream `entity_type` values when available. New UV and AAMVA
  issuers receive the `government_issued_id` scope; automation preserves existing
  issuer metadata and scopes.
- Updated registry entries to the simplified schema and rotated the registry
  signing certificate for the 0.2.x release line.

### Fixed

- Added RSA PKCS#1 v1.5, RSA-PSS, and PSS-only public-key signature verification,
  enforcing declared PSS key restrictions.
- Improved compatibility with separate copies of PKIjs and ASN1.js.

### Removed

- Test issuer data, the `useTestData` option, and the legacy CommonJS static-method
  workaround.
- Issuer-level `trust_lists`; trust-list membership remains on each certificate.
- Metadata fields `government_level`, `official_name`, `institution_name`,
  `institution_type`, `accreditation_body`, and `public_registry_url`.
- The `federated_network` entity type, entity-specific example files, and DID
  roadmap documentation. Issuer support remains X.509-only.

## [0.2.0] - 2026-10-02

### Deprecated

- Accidentally published before the breaking changes for the 0.2.x release line
  were complete. Deprecated on npm; use 0.2.1 or later.

[Unreleased]: https://github.com/universal-verify/trusted-issuer-registry/compare/0.2.2...dev
[0.2.2]: https://github.com/universal-verify/trusted-issuer-registry/compare/0.2.1...0.2.2
[0.2.1]: https://github.com/universal-verify/trusted-issuer-registry/compare/0.1.9...0.2.1
[0.2.0]: https://www.npmjs.com/package/trusted-issuer-registry/v/0.2.0
