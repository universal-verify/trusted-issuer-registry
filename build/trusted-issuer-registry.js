import * as asn1js from 'asn1js';
import { Certificate } from 'pkijs';
import stringify from 'canonical-json';

const MINOR_VERSION = '0.2';

const REGISTRY_URL_BASE = `https://cdn.jsdelivr.net/npm/trusted-issuer-registry@${MINOR_VERSION}`;

const PUBLIC_SIGNING_CERT = `-----BEGIN CERTIFICATE-----
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

const TrustList = {
    UV: 'uv',
    AAMVA_DTS: 'aamva_dts',
};

const TrustScope = {
    GOVERNMENT_ISSUED_ID: 'government_issued_id',
    DOCUMENT_SIGNING: 'document_signing',
};

const RevocationCheckMode = {
    SKIP: 'skip',
    BEST_EFFORT: 'best_effort',
    REQUIRED: 'required',
};

const UntrustedReason = {
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

const base64ToUint8Array = (base64) => {
    if(typeof Buffer === 'function') {
        return new Uint8Array(Buffer.from(base64, 'base64'));
    }

    if(typeof atob !== 'function') {
        throw new Error('No base64 decoder available in this environment');
    }

    const raw = atob(base64);
    const bytes = new Uint8Array(raw.length);
    for (let i = 0; i < raw.length; i++) {
        bytes[i] = raw.charCodeAt(i);
    }
    return bytes;
};

const uint8ArrayToBase64 = (bytes) => {
    if(typeof Buffer === 'function') {
        return Buffer.from(bytes).toString('base64');
    }

    if(typeof btoa !== 'function') {
        throw new Error('No base64 encoder available in this environment');
    }

    let binary = '';
    for (let i = 0; i < bytes.length; i++) {
        binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary);
};

const bufferToBase64Url = (bufferSource) => {
    const bytes = bufferSource instanceof Uint8Array
        ? bufferSource
        : ArrayBuffer.isView(bufferSource)
            ? new Uint8Array(bufferSource.buffer, bufferSource.byteOffset, bufferSource.byteLength)
            : new Uint8Array(bufferSource);

    return uint8ArrayToBase64(bytes)
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=+$/, '');
};

const padOrTrimUint8Array = (bytes, length) => {
    if (bytes.length === length) return bytes;
    if (bytes.length > length) return bytes.slice(bytes.length - length);

    const padded = new Uint8Array(length);
    padded.set(bytes, length - bytes.length);
    return padded;
};

const SUBJECT_KEY_IDENTIFIER_OID = '2.5.29.14';
const SUBJECT_ATTRIBUTE_NAMES = {
    '2.5.4.3': 'commonName',
    '2.5.4.6': 'country',
    '2.5.4.7': 'locality',
    '2.5.4.8': 'state',
    '2.5.4.10': 'organization',
    '2.5.4.11': 'organizationalUnit',
};

const parsePemCertificate = (pemString) => {
    if(typeof pemString !== 'string') {
        throw new Error('PEM certificate must be a string');
    }

    const pemContent = pemString
        .replace(/-----BEGIN CERTIFICATE-----/, '')
        .replace(/-----END CERTIFICATE-----/, '')
        .replace(/\s/g, '');

    const bytes = base64ToUint8Array(pemContent);
    const certBuffer = bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength);
    const asn1 = asn1js.fromBER(certBuffer);
    if(asn1.offset === -1) {
        throw new Error('Unable to parse PEM certificate');
    }
    return new Certificate({ schema: asn1.result });
};

const certificateToPem = (x509Cert) => {
    const certBytes = new Uint8Array(x509Cert.toSchema().toBER());
    const base64 = uint8ArrayToBase64(certBytes);
    const pemLines = [];
    for (let i = 0; i < base64.length; i += 64) {
        pemLines.push(base64.slice(i, i + 64));
    }

    return `-----BEGIN CERTIFICATE-----\n${pemLines.join('\n')}\n-----END CERTIFICATE-----`;
};

const getSubjectKeyIdentifier = (x509Cert) => {
    if(!x509Cert) return null;
    const subjectKeyId = x509Cert.extensions?.find(ext => ext.extnID === SUBJECT_KEY_IDENTIFIER_OID);
    if (!subjectKeyId) return null;

    try {
        const skidValue = asn1js.fromBER(subjectKeyId.extnValue.valueBlock.valueHex);
        if(skidValue.offset === -1) return null;
        const valueHex = skidValue.result.valueBlock.valueHexView || skidValue.result.valueBlock.valueHex;
        if (valueHex) return bufferToBase64Url(valueHex);
    } catch (e) {
        console.error('Could not parse SubjectKeyIdentifier value', e);
    }
    return null;
};

const getCertificateSubject = (x509Cert) => {
    const subject = {};
    const attributes = x509Cert?.subject?.typesAndValues || [];
    for (const attribute of attributes) {
        const name = SUBJECT_ATTRIBUTE_NAMES[attribute.type];
        if(!name) continue;
        const value = getAttributeValue(attribute);
        if(value) subject[name] = value;
    }
    return subject;
};

const getCertificateDisplayName = (x509Cert) => {
    const subject = getCertificateSubject(x509Cert);
    return subject.organization || subject.commonName || null;
};

const verifySignatureWithPem = async (pemKey, signature, data) => {
    try {
        const pemContent = pemKey
            .replace(/-----BEGIN [^-]+-----/, '')
            .replace(/-----END [^-]+-----/, '')
            .replace(/\s+/g, '');

        // Convert base64 to binary
        const bytes = base64ToUint8Array(pemContent);

        const asn1 = asn1js.fromBER(bytes.buffer);
        const cert = new Certificate({ schema: asn1.result });
        const publicKeyInfo = cert.subjectPublicKeyInfo;
        if (!publicKeyInfo || !publicKeyInfo.algorithm || !publicKeyInfo.algorithm.algorithmId) {
            console.error('Parsed publicKeyInfo:', publicKeyInfo);
            throw new Error('Could not extract algorithm information from public key');
        }

        const webCryptoAlg = getWebCryptoAlgorithmFromOid(publicKeyInfo);

        // Convert to SPKI format for Web Crypto
        const spkiBytes = publicKeyInfo.toSchema().toBER();
        const spkiKey = await crypto.subtle.importKey(
            'spki',
            spkiBytes,
            webCryptoAlg,
            false,
            ['verify']
        );

        // Convert signature from base64 to ArrayBuffer
        let signatureBuffer;
        if (webCryptoAlg.name === 'ECDSA') {
            let rsLen = 32; // Default P-256
            if (webCryptoAlg.namedCurve === 'P-384') rsLen = 48;
            if (webCryptoAlg.namedCurve === 'P-521') rsLen = 66;
            // For ECDSA, convert DER signature to raw format
            signatureBuffer = convertDerSignatureToRaw(signature, rsLen);
        } else {
            // For RSA, use as-is
            signatureBuffer = base64ToUint8Array(signature).buffer;
        }

        const verified = await crypto.subtle.verify(webCryptoAlg, spkiKey, signatureBuffer, data);
        return verified;
    } catch (error) {
        console.error('Error converting PEM to SPKI key:', error);
        throw error;
    }
};

function getAttributeValue(attribute) {
    const valueBlock = attribute?.value?.valueBlock;
    if(!valueBlock) return null;
    if(typeof valueBlock.value === 'string') return valueBlock.value;
    if(valueBlock.valueHexView || valueBlock.valueHex) {
        const bytes = valueBlock.valueHexView || new Uint8Array(valueBlock.valueHex);
        try {
            return new TextDecoder().decode(bytes).replace(/\0/g, '');
        } catch (error) {
            return null;
        }
    }
    return null;
}

// Function to convert DER signature to raw format for ECDSA
function convertDerSignatureToRaw(base64Signature, rsLen) {
    try {
        // Decode base64 to binary
        const derBytes = base64ToUint8Array(base64Signature);

        // Parse DER structure
        const asn1 = asn1js.fromBER(derBytes.buffer);

        // DER signature should be SEQUENCE { INTEGER r, INTEGER s }
        if (asn1.result.valueBlock.value.length !== 2) {
            throw new Error('Invalid DER signature structure');
        }

        const r = asn1.result.valueBlock.value[0];
        const s = asn1.result.valueBlock.value[1];

        // Extract r and s values as byte arrays
        const rBytes = new Uint8Array(r.valueBlock.valueHex);
        const sBytes = new Uint8Array(s.valueBlock.valueHex);

        // For P-256, each value should be 32 bytes
        const rPadded = padOrTrimUint8Array(rBytes, rsLen);
        const sPadded = padOrTrimUint8Array(sBytes, rsLen);

        // Concatenate r and s
        const rawSignature = new Uint8Array(rsLen * 2);
        rawSignature.set(rPadded, 0);
        rawSignature.set(sPadded, rsLen);

        return rawSignature.buffer;
    } catch (error) {
        console.error('Error converting DER signature to raw:', error);
        throw error;
    }
}

function getWebCryptoAlgorithmFromOid(publicKeyInfo) {
    const algorithmOid = publicKeyInfo.algorithm.algorithmId;
    const algorithmParams = publicKeyInfo.algorithm.algorithmParams;

    let oidString;
    if (algorithmOid && typeof algorithmOid === 'object' && algorithmOid.valueBlock && typeof algorithmOid.valueBlock.toString === 'function') {
        oidString = algorithmOid.valueBlock.toString();
    } else if (typeof algorithmOid === 'string') {
        oidString = algorithmOid;
    } else {
        throw new Error('Unsupported algorithmOid format');
    }

    switch (oidString) {
        case '1.2.840.10045.2.1': // ecPublicKey
            // Parse the curve parameters to determine the specific curve
            let curveOid;
            if (algorithmParams && typeof algorithmParams === 'object' && algorithmParams.valueBlock && typeof algorithmParams.valueBlock.toString === 'function') {
                curveOid = algorithmParams.valueBlock.toString();
            } else if (typeof algorithmParams === 'string') {
                curveOid = algorithmParams;
            } else {
                curveOid = undefined;
            }
            switch (curveOid) {
                case '1.2.840.10045.3.1.7': // P-256
                    return { name: 'ECDSA', namedCurve: 'P-256', hash: { name: 'SHA-256' } };
                case '1.3.132.0.34': // P-384
                    return { name: 'ECDSA', namedCurve: 'P-384', hash: { name: 'SHA-384' } };
                case '1.3.132.0.35': // P-521
                    return { name: 'ECDSA', namedCurve: 'P-521', hash: { name: 'SHA-512' } };
                case undefined:
                    // Default to P-256 if no parameters provided
                    return { name: 'ECDSA', namedCurve: 'P-256', hash: { name: 'SHA-256' } };
                default:
                    throw new Error(`Unsupported EC curve: ${curveOid}`);
            }
        case '1.2.840.113549.1.1.1': // rsaEncryption
            return { name: 'RSASSA-PKCS1-v1_5' };
        case '1.2.840.113549.1.1.10': // rsassaPss
            return { name: 'RSA-PSS' };
        default:
            throw new Error(`Unsupported algorithm OID: ${oidString}`);
    }
}

const buildUserTrustedIssuers = (trustedIssuerCertificates = []) => {
    if(!Array.isArray(trustedIssuerCertificates)) {
        throw new Error('trustedIssuerCertificates must be an array');
    }

    const userTrustedIssuers = Object.create(null);
    for(const trustedIssuerCertificate of trustedIssuerCertificates) {
        const { subjectKeyIdentifier, issuer } = normalizeTrustedIssuerCertificate(trustedIssuerCertificate);
        const existingIssuer = userTrustedIssuers[subjectKeyIdentifier];
        if(existingIssuer) {
            existingIssuer.certificates.push(...issuer.certificates);
        } else {
            userTrustedIssuers[subjectKeyIdentifier] = issuer;
        }
    }

    return userTrustedIssuers;
};

const normalizeTrustedIssuerCertificate = (trustedIssuerCertificate) => {
    const options = typeof trustedIssuerCertificate === 'string'
        ? { data: trustedIssuerCertificate }
        : { ...trustedIssuerCertificate };

    if(typeof options.data !== 'string') {
        throw new Error('trustedIssuerCertificates entries must be PEM strings or objects with a data PEM string');
    }
    if(options.format && options.format !== 'pem') {
        throw new Error(`Unsupported issuer certificate format: ${options.format}`);
    }

    const parsedCertificate = parsePemCertificate(options.data);
    const subjectKeyIdentifier = getSubjectKeyIdentifier(parsedCertificate);
    if(!subjectKeyIdentifier) {
        throw new Error('trustedIssuerCertificates entries must include a Subject Key Identifier extension');
    }

    const issuerId = `x509_aki:${subjectKeyIdentifier}`;
    const subject = getCertificateSubject(parsedCertificate);
    const display = mergeDefined(
        { name: getCertificateDisplayName(parsedCertificate) || issuerId },
        options.display || {}
    );

    const entityMetadata = mergeDefined(
        {
            country: subject.country || '',
            region: subject.state ? subject.state.replace('US-', '') : undefined,
        },
        options.entity_metadata || {}
    );

    return {
        subjectKeyIdentifier,
        issuer: {
            issuer_id: issuerId,
            entity_type: options.entity_type || 'other',
            entity_metadata: entityMetadata,
            display,
            trust_scopes: Array.isArray(options.trust_scopes) ? [...options.trust_scopes] : [],
            certificates: [
                {
                    data: certificateToPem(parsedCertificate),
                    format: 'pem',
                    trust_lists: ['user_provided'],
                },
            ],
        },
    };
};

const mergeDefined = (...objects) => {
    const merged = {};
    for(const object of objects) {
        for(const [key, value] of Object.entries(object)) {
            if(value !== undefined) merged[key] = value;
        }
    }
    return merged;
};

class Registry {
    constructor(options = {}) {
        this._cacheEnabled = options.cacheEnabled ?? true;
        this._cacheTTL = options.cacheTTL ?? 1000 * 60 * 60 * 24; // 24 hours
        this._crl = normalizeCRLConfig(options);
        this._userTrustedIssuers = buildUserTrustedIssuers(options.trustedIssuerCertificates ?? []);
        this._urlBase = REGISTRY_URL_BASE;
        this._cache = new Map();
        this._crlCache = new Map();
        this._deprecationCache = null;
    }

    async getEndOfLifeDate() {
        if (this._cacheEnabled && this._deprecationCache && this._deprecationCache.expiresAt > Date.now()) return this._copyDate(this._deprecationCache.endOfLifeDate);

        const response = await fetch(`${this._urlBase}/deprecation_notice.json`);
        let endOfLifeDate = null;
        if (response.ok) {
            const deprecationNotice = await response.json();
            if(deprecationNotice.version) {
                const [major, minor] = deprecationNotice.version.split('.').map(Number);
                const [currentMajor, currentMinor] = MINOR_VERSION.split('.').map(Number);
                if(!(major < currentMajor || (major === currentMajor && minor < currentMinor))) endOfLifeDate = new Date(deprecationNotice.end_of_life * 1000);
            }
        } else if (response.status === 404) {
            endOfLifeDate = null;
        } else {
            throw new Error(`Failed to fetch deprecation notice: ${response.status} ${response.statusText || ''}`.trim());
        }

        if (this._cacheEnabled) {
            this._deprecationCache = {
                endOfLifeDate,
                expiresAt: Date.now() + this._cacheTTL
            };
        }
        return this._copyDate(endOfLifeDate);
    }

    async getIssuerFromX509AKI(x509aki) {
        const userTrustedIssuer = this._userTrustedIssuers[x509aki];
        if(userTrustedIssuer) return this._deepCopy(userTrustedIssuer);

        if (this._cacheEnabled) {
            const cachedIssuer = this._cache.get(x509aki);
            if(cachedIssuer) {
                if(cachedIssuer.expiresAt > Date.now()) return this._deepCopy(cachedIssuer.issuer);
                this._cache.delete(x509aki);
            }
        }

        const response = await fetch(`${this._urlBase}/issuers/x509_aki/${x509aki}.json`);
        if (response.ok) {
            const issuer = await response.json();
            const verified = await this._verifyIssuer(issuer);
            if (!verified) return null;
            if (this._cacheEnabled) {
                this._cache.set(x509aki, {
                    issuer,
                    expiresAt: Date.now() + this._cacheTTL
                });
            }
            return this._deepCopy(issuer);
        } else if (response.status === 404) {
            if (this._cacheEnabled) {
                this._cache.set(x509aki, {
                    issuer: null,
                    expiresAt: Date.now() + this._cacheTTL
                });
            }
        } else {
            throw new Error(`Failed to fetch issuer ${x509aki}: ${response.status} ${response.statusText || ''}`.trim());
        }

        return null;
    }

    async resolveCertificateTrust(_certificate) {
        throw new Error('resolveCertificateTrust is not implemented yet');
    }

    async _verifyIssuer(issuer) {
        const issuerCopy = { ...issuer };
        const signature = issuerCopy.signature;
        delete issuerCopy.signature;
        const issuerString = stringify(issuerCopy);

        let verified = false;
        try {
            const issuerData = new TextEncoder().encode(issuerString).buffer;
            verified = await verifySignatureWithPem(PUBLIC_SIGNING_CERT, signature, issuerData);
        } catch (e) {
            console.error('Issuer signature verification failed', e);
        }
        return verified;
    }

    _deepCopy(obj) {
        return JSON.parse(JSON.stringify(obj));
    }

    _copyDate(date) {
        return date ? new Date(date.getTime()) : null;
    }

    static minorVersion = MINOR_VERSION;
}

const normalizeCRLConfig = (options = {}) => {
    const crl = options.crl || {};
    const mode = crl.mode ?? RevocationCheckMode.SKIP;
    if(!Object.values(RevocationCheckMode).includes(mode)) {
        throw new Error(`Unsupported CRL check mode: ${mode}`);
    }

    return {
        mode: mode,
        timeout: crl.timeout ?? 5000,
    };
};

export { Registry, RevocationCheckMode, TrustList, TrustScope, UntrustedReason, verifySignatureWithPem };
