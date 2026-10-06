# Trusted Issuer Registry

Trusted Issuer Registry provides a signed source of trusted issuers and a JavaScript library for verifying whether they issued a certificate.

Use registry issuers, your own trusted issuer certificates without querying the registry, or both. The library handles signature verification, validity dates, and optional CRL revocation checks, returning issuer details and trust results.

## Registry Overview

The Trusted Issuer Registry aggregates and validates issuer information from multiple authoritative trust lists, including:

- **[AAMVA DTS](https://www.aamva.org/identity/mobile-driver-license-digital-trust-service)** - American Association of Motor Vehicle Administrators' Digital Trust Service
- **[UV](https://github.com/universal-verify/trust-list)** - Universal Verify's compilation of Apple recommended issuers for digital credential verification

All issuer data is cryptographically signed to ensure integrity and authenticity, providing a reliable foundation for digital credential verification systems.

Registry lookups target the latest published patch in the library's minor version, so issuer updates don't require a library upgrade (subject to library and [CDN caching](https://github.com/jsdelivr/jsdelivr#caching)).

## Trust Model

This registry operates on a robust trust model designed for enterprise and financial applications:

- **Cryptographic Verification**: All issuer metadata is signed using NIST P-256 (prime256v1) curve
- **Immutable Audit Trail**: All changes are publicly auditable via GitHub's commit history
- **Vetted Sources**: Only issuers from carefully vetted trust lists are included
- **Transparent Governance**: Clear policies for inclusion, removal, and updates

For detailed information about our trust model and risk considerations, see:
- [Trust Policy](TRUST_POLICY.md) - Criteria for upstream trust list inclusion
- [Trust and Risk Model](TRUST_AND_RISK_MODEL.md) - Comprehensive threat model and mitigation strategies

## Quick Start

Install the package:

```bash
npm install trusted-issuer-registry
```

Resolve trust for a PEM-encoded certificate or a parsed PKIjs `Certificate`:

```javascript
import { Registry, TrustList } from 'trusted-issuer-registry';

const registry = new Registry();

const result = await registry.resolveCertificateTrust(certificatePem, {
    trustLists: [TrustList.UV, TrustList.AAMVA_DTS],
});

if (result.trusted) {
    console.log('Trusted issuer:', result.issuer.display.name);
    console.log('Entity type:', result.issuer.entity_type);
    console.log('Certificates:', result.issuer.certificates);
} else {
    console.log('Certificate not trusted:', result.untrustedReasons);
}
```

TypeScript declarations are included for the package and all build variants, with support for strict NodeNext and browser/bundler projects. No separate `@types` package is needed.

## API Reference

### Constants

#### `TrustList`

Supported registry trust lists for `resolveCertificateTrust`:

| Constant | Value | Description |
| --- | --- | --- |
| `TrustList.UV` | `uv` | Issuers trusted by Universal Verify |
| `TrustList.AAMVA_DTS` | `aamva_dts` | Issuers trusted by the AAMVA Digital Trust Service |

#### `TrustScope`

Issuer trust scopes that can be requested through `resolveCertificateTrust`:

| Constant | Value | Description |
| --- | --- | --- |
| `TrustScope.GOVERNMENT_ISSUED_ID` | `government_issued_id` | Government-issued identity documents |
| `TrustScope.DOCUMENT_SIGNING` | `document_signing` | Documents signed by the issuer |

#### `RevocationCheckMode`

Controls certificate revocation checking through CRLs:

| Constant | Value | Description |
| --- | --- | --- |
| `RevocationCheckMode.SKIP` | `skip` | Do not check revocation (default) |
| `RevocationCheckMode.BEST_EFFORT` | `best_effort` | Reject confirmed revocation, but permit undetermined status |
| `RevocationCheckMode.REQUIRED` | `required` | Reject confirmed revocation and undetermined status |

Status is undetermined when the CRL check cannot establish revocation status, such as when CRLs are missing, unavailable, or invalid. A verified stale CRL can still establish revocation, but cannot establish non-revoked status. CRLs are checked only against issuer certificates that validate the input certificate's signature.

#### `UntrustedReason`

Stable codes for root and certificate-level `untrustedReasons`. Values are lowercase versions of the constant names, not human-readable messages.

| Constant | Description |
| --- | --- |
| `UntrustedReason.CERTIFICATE_MISSING` | Certificate is required to determine issuer trust |
| `UntrustedReason.CERTIFICATE_AKI_MISSING` | Certificate does not contain an Authority Key Identifier |
| `UntrustedReason.CERTIFICATE_NOT_YET_VALID` | Certificate is not yet valid |
| `UntrustedReason.CERTIFICATE_EXPIRED` | Certificate is expired |
| `UntrustedReason.CERTIFICATE_REVOKED` | Certificate has been revoked by CRL |
| `UntrustedReason.REVOCATION_STATUS_UNDETERMINED` | Unable to determine certificate revocation status |
| `UntrustedReason.ISSUER_FETCH_FAILED` | Unable to retrieve issuer from trusted issuer registry |
| `UntrustedReason.ISSUER_CERTIFICATE_NOT_FOUND` | No issuer certificate found to validate the input certificate |
| `UntrustedReason.CERTIFICATE_SIGNATURE_VERIFICATION_FAILED` | Certificate signature could not be verified with the issuer certificate |
| `UntrustedReason.ISSUER_CERTIFICATE_NOT_YET_VALID` | Issuer certificate is not yet valid |
| `UntrustedReason.ISSUER_CERTIFICATE_EXPIRED` | Issuer certificate is expired |
| `UntrustedReason.ISSUER_CERTIFICATE_NOT_IN_TRUST_LISTS` | Issuer certificate is not trusted by the requested trust lists |
| `UntrustedReason.ISSUER_MISSING_REQUIRED_TRUST_SCOPE` | Issuer does not have the trust scope requested |

### Registry

#### `new Registry(options = {})`

Creates a registry client with optional user-provided issuers, revocation checking, and request caching.

**Constructor options:**

| Option | Type | Default | Description |
| --- | --- | --- | --- |
| `trustedIssuerCertificates` | `Array<string\|Object>` | `[]` | User-provided PEM-encoded issuer certificates, optionally with issuer metadata |
| `revocationCheckMode` | `string` | `RevocationCheckMode.SKIP` | CRL checking mode from `RevocationCheckMode` |
| `timeout` | `number` | `10000` | Timeout in milliseconds for each network request, including reading its response body |
| `cacheEnabled` | `boolean` | `true` | Cache issuer files, deprecation notices, and CRLs in memory |
| `cacheTTL` | `number` | `86400000` | Cache lifetime in milliseconds (24 hours) |

`timeout` applies to issuer, deprecation, and CRL requests. It is not a deadline for the entire trust resolution operation.

Each `trustedIssuerCertificates` entry can be a PEM string or an object with these fields:

| Field | Type | Required | Default or Description |
| --- | --- | --- | --- |
| `data` | `string` | Yes | PEM-encoded certificate |
| `format` | `string` | No | `pem` (the only supported format) |
| `trust_scopes` | `Array<string>` | No | `[]` |
| `entity_type` | `string` | No | `other` |
| `entity_metadata` | `Object` | No | Country and region derived from the certificate subject, when available |
| `display` | `Object` | No | Name derived from the certificate's organization or common name, falling back to its issuer ID |

Provided metadata overrides certificate-derived defaults. Certificates must contain a Subject Key Identifier (SKI); entries with the same SKI are grouped into one issuer. Each certificate receives `trust_lists: ['user_provided']`. User-provided certificates bypass registry trust-list filtering, but still undergo signature, validity, optional scope, and optional revocation checks.

Unsupported revocation modes, malformed issuer certificates, and certificates without an SKI throw an error.

**Example:**

```javascript
import { Registry, RevocationCheckMode, TrustScope } from 'trusted-issuer-registry';

const registry = new Registry({
    trustedIssuerCertificates: [
        issuerPem,
        {
            data: anotherIssuerPem,
            format: 'pem',
            trust_scopes: [TrustScope.DOCUMENT_SIGNING],
            entity_type: 'educational_institution',
            entity_metadata: { country: 'US' },
            display: { name: 'Example University' },
        },
    ],
    revocationCheckMode: RevocationCheckMode.REQUIRED,
    timeout: 10000,
    cacheEnabled: true,
    cacheTTL: 86400000,
});
```

**Caching:**

Successful downloads and HTTP 404s are cached for up to `cacheTTL` when caching is enabled; issuers require valid registry signatures. Network errors, timeouts, and other HTTP errors aren't cached. Each instance retains at most 1,024 responses using LRU eviction, with activity-triggered expiry sweeps at most once per minute. Concurrent downloads are shared even with caching disabled. Cached CRLs are validated per certificate, and `nextUpdate` shortens their TTL only when in the future and sooner than normal expiry.

#### `Registry.minorVersion`

The minor version of the registry used by this SDK.

**Type:** `string`

**Example:**

```javascript
console.log(Registry.minorVersion); // '0.2'
```

### Registry Methods

#### `registry.resolveCertificateTrust(certificate, options = {})`

Determines whether a certificate was issued by a trusted issuer, returning issuer metadata and trust results for all of that issuer's certificates.

**Parameters:**

| Parameter | Type | Description |
| --- | --- | --- |
| `certificate` | `string\|Certificate` | PEM-encoded certificate or parsed PKIjs `Certificate` |
| `options` | `Object` | Optional trust-list and scope restrictions |

**Options:**

| Option | Type | Default | Description |
| --- | --- | --- | --- |
| `trustLists` | `Array<string>` | `[]` | Registry trust lists to use, from `TrustList`. An empty array uses only user-provided issuers and does not query the registry |
| `trustScope` | `string` | `undefined` | Required issuer scope from `TrustScope`. Omitted, `undefined`, or `null` skips scope checking |

Registry certificates must belong to at least one requested trust list. User-provided certificates bypass that filter. When `trustScope` is set, the issuer's `trust_scopes` are checked for every certificate, including user-provided certificates.

**Returns:** `Promise<Object>` - Certificate trust result.

**Example:**

```javascript
const result = await registry.resolveCertificateTrust(certificatePem, {
    trustLists: [TrustList.AAMVA_DTS],
    trustScope: TrustScope.GOVERNMENT_ISSUED_ID,
});

console.log(result.trusted);
console.log(result.untrustedReasons);
console.log(result.issuer?.certificates);
```

**Example response (with revocation checking skipped):**

```json
{
  "trusted": true,
  "issuer": {
    "issuer_id": "x509_aki:...",
    "entity_type": "government",
    "entity_metadata": { "country": "US", "region": "VA" },
    "display": { "name": "Example Issuer" },
    "trust_scopes": ["government_issued_id"],
    "certificates": [
      {
        "data": "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----",
        "format": "pem",
        "trust_lists": ["user_provided", "aamva_dts"],
        "trusted": true,
        "revocationStatus": "not_checked"
      },
      {
        "data": "-----BEGIN CERTIFICATE-----\n...another certificate...\n-----END CERTIFICATE-----",
        "format": "pem",
        "trust_lists": ["aamva_dts"],
        "trusted": false,
        "revocationStatus": "not_checked",
        "untrustedReasons": ["issuer_certificate_expired"]
      }
    ]
  }
}
```

**Response fields:**

| Field | Type | Description |
| --- | --- | --- |
| `trusted` | `boolean` | Whether the input certificate passes all requested trust checks |
| `issuer` | `Object` | Issuer metadata and all issuer certificates; omitted when no issuer is found |
| `untrustedReasons` | `Array<string>` | Failure reasons from `UntrustedReason`, including those of the selected issuer certificate; omitted when empty |
| `issuer.certificates[].trusted` | `boolean` | Whether this issuer certificate satisfies the trust checks for the input certificate |
| `issuer.certificates[].revocationStatus` | `string` | `not_checked`, `not_revoked`, or `revoked` |
| `issuer.certificates[].untrustedReasons` | `Array<string>` | Reasons this issuer certificate cannot establish trust; omitted when empty |

**Trust evaluation:**

- User-provided issuer metadata takes precedence over registry metadata. Trust scopes and certificates are combined, with identical PEM certificates merged along with their trust lists. User-provided certificates appear first in input order, followed by unique registry certificates in registry order.
- The root uses the first trusted issuer certificate, or the certificate with the fewest untrusted reasons when none are trusted. List order breaks ties, and input certificate validity reasons are also included at the root.
- Missing input or a missing AKI returns only `certificate_missing` or `certificate_aki_missing`, without looking up an issuer. Not-yet-valid or expired input certificates still undergo issuer evaluation.
- A registry fetch failure adds `issuer_fetch_failed` only when no user-provided certificate is trusted. Missing issuers or empty certificate lists add `issuer_certificate_not_found`.
- The issuer object has no `untrustedReasons` field. Its `signature` is also omitted because merged metadata and runtime trust results are not covered by the registry signature. Registry signatures are verified before merging.

Malformed certificate input rejects the promise with a parsing error.

#### `registry.getIssuerFromX509AKI(x509aki)`

Retrieves and merges issuer information without evaluating certificate trust. The registry is always checked, using cached data when available, even when a user-provided issuer exists.

**Parameters:**

- `x509aki` (string): Base64url-encoded X.509 Authority Key Identifier, without the `x509_aki:` prefix.

**Returns:** `Promise<Object|null>` - Merged issuer data, or `null` when no issuer is found.

User metadata takes precedence, scopes and certificates are combined, and user-provided certificates appear first. A registry 404 still allows a user-provided issuer to be returned. Registry request failures reject the lookup even when a user-provided issuer exists.

Merged results omit `signature`. When no user-provided issuer matches, the original signed registry data is returned with its signature. This method does not add certificate trust results.

**Example:**

```javascript
const issuer = await registry.getIssuerFromX509AKI('TprRzaFBJ1SLjJsO01tlLCQ4YF0');
```

#### `registry.getEndOfLifeDate()`

Retrieves the applicable deprecation notice for the registry minor version.

**Returns:** `Promise<Date|null>` - End-of-life date, or `null` when no applicable deprecation notice exists.

Request failures and malformed deprecation notices reject the promise.

**Example:**

```javascript
const endOfLifeDate = await registry.getEndOfLifeDate();
if (endOfLifeDate) {
    console.log('Registry will be deprecated on:', endOfLifeDate);
}
```

### Utility Functions

These are standalone named exports and do not require a `Registry` instance.

#### `parsePemCertificate(pemString)`

Parses a PEM-encoded X.509 certificate without verifying its signature or trust.

**Parameters:**

- `pemString` (string): PEM-encoded certificate.

**Returns:** `Certificate` - Parsed PKIjs `Certificate`.

Malformed input throws a parsing error.

**Example:**

```javascript
import { parsePemCertificate } from 'trusted-issuer-registry';

const certificate = parsePemCertificate(certificatePem);
```

#### `certificateToPem(certificate)`

Serializes a parsed X.509 certificate to PEM.

**Parameters:**

- `certificate` (Certificate): Parsed PKIjs `Certificate`, including objects from a separate copy of PKIjs.

**Returns:** `string` - PEM-encoded certificate.

**Example:**

```javascript
import { certificateToPem } from 'trusted-issuer-registry';

const pem = certificateToPem(certificate);
```

#### `verifyCertificateSignature(certificate, issuerCertificate)`

Verifies the signature on a certificate using an issuer certificate's public key, also checking that the issuer name matches the issuer certificate's subject.

**Parameters:**

- `certificate` (string|Certificate): PEM string or parsed PKIjs certificate whose signature should be verified.
- `issuerCertificate` (string|Certificate): PEM string or parsed PKIjs issuer certificate supplying the public key.

**Returns:** `Promise<boolean>` - Whether the issuer name matches and the signature verifies.

Inputs may come from different PKIjs copies. Objects from the SDK's own copy are reused; foreign objects are normalized before verification. Malformed certificate input rejects the promise with a parsing error.

This function does not evaluate validity dates, revocation, trust lists, trust scopes, or a full certificate chain. Pass the same certificate as both arguments to verify a self-signed certificate; a valid self-signature does not establish trust.

**Example:**

```javascript
import { verifyCertificateSignature } from 'trusted-issuer-registry';

const verified = await verifyCertificateSignature(certificatePem, issuerPem);
```

#### `verifySignatureWithPem(pemKey, signature, data, options?)`

Verifies a signature over supplied data using the public key from a PEM-encoded signing certificate. This verifies a data signature, not the signature on the certificate itself.

**Parameters:**

- `pemKey` (string): PEM-encoded X.509 signing certificate.
- `signature` (string): Base64-encoded signature. ECDSA signatures must be DER-encoded before Base64 encoding.
- `data` (ArrayBuffer|TypedArray|DataView): The exact bytes that were signed.
- `options` (SignatureVerificationOptions, optional): Signature algorithm parameters. The EC curve is read from the certificate.

| Option | Description |
|--------|-------------|
| `name` | `ECDSA`, `RSASSA-PKCS1-v1_5`, or `RSA-PSS`. Required for RSA; defaults to `ECDSA` for EC certificates. |
| `hash` | Hash algorithm, such as `SHA-256` or `{ name: 'SHA-256' }`. Required for RSA. ECDSA defaults to SHA-256 for P-256, SHA-384 for P-384, and SHA-512 for P-521. |
| `saltLength` | Non-negative integer salt length in bytes. Required for RSA-PSS, including when the salt length is zero. |

RSA has no implicit defaults. Use the parameters specified by the signed data's format; they cannot generally be inferred from the certificate. ECDSA's default hash can also be overridden. Verification uses only the selected parameters without retrying other combinations.

PSS-only public keys are supported, with any declared hash and minimum salt-length restrictions enforced. RSA-PSS requires MGF1 with the same hash as the signature and the standard trailer field.

**Returns:** `Promise<boolean>` - Whether the signature verifies.

Malformed inputs, unsupported algorithms, and cryptographic processing errors reject the promise. This function does not evaluate certificate trust.

**Example:**

```javascript
import { verifySignatureWithPem } from 'trusted-issuer-registry';

const verified = await verifySignatureWithPem(
    signingCertificatePem,
    signatureBase64,
    new TextEncoder().encode(signedText)
);

const rsaPssVerified = await verifySignatureWithPem(
    rsaSigningCertificatePem,
    rsaSignatureBase64,
    signedBytes,
    { name: 'RSA-PSS', hash: 'SHA-256', saltLength: 32 }
);
```

## Direct HTTP Access

You can also access issuer data directly via HTTP requests to a CDN:

```bash
# Get Apple issuer by X.509 AKI
curl https://cdn.jsdelivr.net/npm/trusted-issuer-registry@0.2/issuers/x509_aki/ZQ9wReJ1csNhZ3sfoWXy5Oxv0ac.json

# Check deprecation notice
curl https://cdn.jsdelivr.net/npm/trusted-issuer-registry@0.2/deprecation_notice.json
```

The URL format is:
```
https://cdn.jsdelivr.net/npm/trusted-issuer-registry@{minor_version}/issuers/x509_aki/{x509aki}.json
```

Replace `{minor_version}` with the registry minor version (e.g., `0.2`) and `{x509aki}` with the X.509 Authority Key Identifier.

## Issuer Data Format

Each issuer entry follows the schema defined in `trusted-issuer.schema.json`. Here's an example:

```json
{
  "issuer_id": "x509_aki:3-BJ8g1-X200DZEo-i9MFTtNh0U",
  "entity_type": "government",
  "entity_metadata": {
    "country": "US",
    "region": "AZ"
  },
  "display": {
    "name": "Arizona Department of Transportation"
  },
  "trust_scopes": ["government_issued_id"],
  "certificates": [
    {
      "data": "-----BEGIN CERTIFICATE-----\n...",
      "format": "pem",
      "trust_lists": ["uv", "aamva_dts"]
    }
  ],
  "signature": "..."
}
```

### Fields Explained

- **`issuer_id`**: Unique identifier used by digital credentials to reference issuers/certificates
- **`entity_type`**: Type of organization (government, commercial, educational, etc.)
- **`entity_metadata`**: Additional metadata about the entity
- **`display`**: Human-readable display information
- **`trust_scopes`**: Contexts where this issuer should be trusted, such as government-issued ID verification or document signing
- **`certificates`**: Array of certificates using the given AKI
- **Certificate `trust_lists`**: Source trust lists that vouch for each certificate

For the complete schema definition, see [trusted-issuer.schema.json](trusted-issuer.schema.json).

### Inspecting Issuer Certificates

To decode and print all X.509 certificates embedded in an issuer file:

```bash
npm run decode-certificate -- issuers/x509_aki/TprRzaFBJ1SLjJsO01tlLCQ4YF0.json
```

The command uses the local `openssl` binary to print decoded certificate details.

To decode only one certificate from a multi-certificate issuer file, pass a 1-based index:

```bash
npm run decode-certificate -- issuers/x509_aki/TprRzaFBJ1SLjJsO01tlLCQ4YF0.json --index 1
```

## Versioning and Deprecation

The registry uses semantic versioning with the following approach:

- **Minor version updates** indicate schema changes or breaking updates
- **Deprecation notices** are published for old minor versions 90 days in advance of its end-of-life date
- **Old minor versions** will continue to receive issuer updates until the end-of-life date

### Checking for Deprecation

```javascript
const registry = new Registry();
const endOfLifeDate = await registry.getEndOfLifeDate();

if (endOfLifeDate && endOfLifeDate < new Date()) {
    console.warn('This registry version has been deprecated');
}
```

Or check directly:

```bash
curl https://cdn.jsdelivr.net/npm/trusted-issuer-registry@0.1/deprecation_notice.json
```

The deprecation notice format is:

```json
{
  "version": "0.1",
  "end_of_life": 1761782400
}
```

Where `end_of_life` is a Unix timestamp in seconds indicating when that version will be deprecated.

## Security Considerations

- All issuer data is cryptographically signed
- [Signing certificate](public_signing_cert.pem) for verification is included in the package
- Transparent change control via GitHub pull requests

## Contributing

We welcome contributions from the community. Please see our [Trust Policy](TRUST_POLICY.md) for information about requesting support for new trust lists.

Are you a security expert or a company with a security team? We'd love to list you as a contributor in this README in exchange for a security review.

## License

This project is licensed under the Mozilla Public License 2.0.
