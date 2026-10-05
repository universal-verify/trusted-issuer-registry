export const MINOR_VERSION = '0.2';

export const REGISTRY_URL_BASE = `https://cdn.jsdelivr.net/npm/trusted-issuer-registry@${MINOR_VERSION}`;

export const PUBLIC_SIGNING_CERT = `-----BEGIN CERTIFICATE-----
MIIBmjCCAUGgAwIBAgIULVFa5+g4perqTRJKDErRMXThCmAwCgYIKoZIzj0EAwIw
IzEhMB8GA1UEAwwYVW5pdmVyc2FsIFZlcmlmeSBSb290IENBMB4XDTI2MTAwMjEz
MzAyNFoXDTM2MDkyOTEzMzAyNFowIzEhMB8GA1UEAwwYVW5pdmVyc2FsIFZlcmlm
eSBSb290IENBMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEfrzJarNNsjnyngbJ
ZSzXI5gM6x/36RRJ+/v3tle4jaVZ3hXI/lg4Qq/NPOzwxrEZQSOHebOBzg5C9msL
G+73zKNTMFEwHQYDVR0OBBYEFEr6yqRcHLSe64ERXXvnADhfgzkuMB8GA1UdIwQY
MBaAFEr6yqRcHLSe64ERXXvnADhfgzkuMA8GA1UdEwEB/wQFMAMBAf8wCgYIKoZI
zj0EAwIDRwAwRAIgLgTLhVKk/yv7aLvy2XNV224q4iFRL+26F/G3/MKF9dkCIGa4
jw4Og3tKk0nt09p7ZWpg4dOMYxnGL5L8kWM7UDIF
-----END CERTIFICATE-----`;

export const TrustList = {
    UV: 'uv',
    AAMVA_DTS: 'aamva_dts',
};

export const TrustScope = {
    GOVERNMENT_ISSUED_ID: 'government_issued_id',
    DOCUMENT_SIGNING: 'document_signing',
};

export const RevocationCheckMode = {
    SKIP: 'skip',
    BEST_EFFORT: 'best_effort',
    REQUIRED: 'required',
};

export const UntrustedReason = {
    CERTIFICATE_MISSING: 'Certificate is required to determine issuer trust',
    CERTIFICATE_AKI_MISSING: 'Certificate does not contain an Authority Key Identifier',
    CERTIFICATE_NOT_YET_VALID: 'Certificate is not yet valid',
    CERTIFICATE_EXPIRED: 'Certificate is expired',
    CERTIFICATE_REVOKED: 'Certificate has been revoked by CRL',
    REVOCATION_STATUS_UNDETERMINED: 'Unable to determine certificate revocation status',
    ISSUER_FETCH_FAILED: 'Unable to retrieve issuer from trusted issuer registry',
    ISSUER_CERTIFICATE_NOT_FOUND: 'No trusted issuer certificate found to validate the certificate',
    ISSUER_CERTIFICATE_NOT_YET_VALID: 'Issuer certificate is not yet valid',
    ISSUER_CERTIFICATE_EXPIRED: 'Issuer certificate is expired',
    ISSUER_CERTIFICATE_NOT_IN_TRUST_LISTS: 'Issuer certificate is not trusted by the requested trust lists',
    ISSUER_MISSING_REQUIRED_TRUST_SCOPE: 'Issuer does not have the trust scope requested',
};
