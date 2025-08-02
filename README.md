# Trusted Issuer Registry

A comprehensive registry of digital credential issuers sourced from authoritative trust lists. This registry provides cryptographically signed issuer metadata to enable secure digital credential verification across various platforms and applications.

## Overview

The Trusted Issuer Registry aggregates and validates issuer information from multiple authoritative trust lists, including:

- **[AAMVA DTS](https://www.aamva.org/identity/mobile-driver-license-digital-trust-service)** - American Association of Motor Vehicle Administrators' Digital Trust Service
- **[UV](https://github.com/universal-verify/trust-list)** - Universal Verify's compilation of Apple recommended issuers for digital credential verification

All issuer data is cryptographically signed to ensure integrity and authenticity, providing a reliable foundation for digital credential verification systems.

## Trust Model

This registry operates on a robust trust model designed for enterprise and financial applications:

- **Cryptographic Verification**: All issuer metadata is signed using NIST P-256 (prime256v1) curve
- **Immutable Audit Trail**: All changes are publicly auditable via GitHub's commit history
- **Vetted Sources**: Only issuers from carefully vetted trust lists are included
- **Transparent Governance**: Clear policies for inclusion, removal, and updates

For detailed information about our trust model and risk considerations, see:
- [Trust Policy](TRUST_POLICY.md) - Criteria for upstream trust list inclusion
- [Trust and Risk Model](TRUST_AND_RISK_MODEL.md) - Comprehensive threat model and mitigation strategies

## Usage

### NPM Module (Recommended)

Install the package:

```bash
npm install trusted-issuer-registry
```

Use the JavaScript SDK:

```javascript
import TrustedIssuerRegistry from 'trusted-issuer-registry';

const registry = new TrustedIssuerRegistry();

// Get issuer by X.509 AKI
const issuer = await registry.getIssuerFromX509AKI('TprRzaFBJ1SLjJsO01tlLCQ4YF0');
if (issuer) {
    console.log('Issuer found:', issuer.display.name);
    console.log('Entity type:', issuer.entity_type);
    console.log('Certificates:', issuer.certificates.length);
    //Verify signature of your digital credential against the issuer's certificates
}

// Check for deprecation notices
const endOfLifeDate = await registry.getEndOfLifeDate();
if (endOfLifeDate) {
    console.log('Registry will be deprecated on:', endOfLifeDate);
}
```

### Direct HTTP Access

You can also access issuer data directly via HTTP requests to a CDN:

```bash
# Get issuer by X.509 AKI
curl https://cdn.jsdelivr.net/npm/trusted-issuer-registry@0.0/x509_aki/TprRzaFBJ1SLjJsO01tlLCQ4YF0.json

# Check deprecation notice
curl https://cdn.jsdelivr.net/npm/trusted-issuer-registry@0.0/deprecation_notice.json
```

The URL format is:
```
https://cdn.jsdelivr.net/npm/trusted-issuer-registry@{minor_version}/x509_aki/{x509aki}.json
```

Replace `{minor_version}` with the current minor version (e.g., `0.0`) and `{x509aki}` with the X.509 Authority Key Identifier.

## Issuer Data Format

Each issuer entry follows the schema defined in `trusted-issuer.schema.json`. Here's an example:

```json
{
  "issuer_id": "x509_aki:o6sbAJOdtI7_VxKIDCy1e7kIXaM",
  "entity_type": "government",
  "entity_metadata": {
    "country": "US",
    "region": "AZ",
    "government_level": "state",
    "official_name": "Arizona Department of Transportation"
  },
  "display": {
    "name": "Arizona Department of Transportation"
  },
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
- **`certificates`**: Array of certificates using the given AKI
- **`trust_lists`**: Source trust lists that vouch for this issuer

For the complete schema definition, see [trusted-issuer.schema.json](trusted-issuer.schema.json).

## Versioning and Deprecation

The registry uses semantic versioning with the following approach:

- **Minor version updates** indicate schema changes or breaking updates
- **Deprecation notices** are published for old minor versions 90 days in advance of its end-of-life date
- **Old minor versions** will continue to receive issuer updates until the end-of-life date

### Checking for Deprecation

```javascript
const registry = new TrustedIssuerRegistry();
const endOfLifeDate = await registry.getEndOfLifeDate();

if (endOfLifeDate && endOfLifeDate < new Date()) {
    console.warn('This registry version has been deprecated');
}
```

Or check directly:

```bash
curl https://cdn.jsdelivr.net/npm/trusted-issuer-registry@0.0/deprecation_notice.json
```

The deprecation notice format is:

```json
{
  "end_of_life": 1761782400
}
```

Where `end_of_life` is a Unix timestamp in seconds indicating when the current version will be deprecated.

## Future Support

Currently, the registry supports X.509 certificate-based issuers. Support for W3C Decentralized Identifiers (DIDs) will be added as trusted issuers begin adopting this standard.

## Security Considerations

- All issuer data is cryptographically signed
- [Public key](public_signing_key.pem) for verification is included in the package
- Transparent change control via GitHub pull requests

## Contributing

We welcome contributions from the community. Please see our [Trust Policy](TRUST_POLICY.md) for information about requesting support for new trust lists.

Are you a security expert or a company with a security team? We'd love to list you as a contributor in this README in exchange for a security review.

## License

This project is licensed under the Mozilla Public License 2.0.
