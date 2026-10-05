import * as asn1js from 'asn1js';
import { Certificate, getCrypto, setEngine, CryptoEngine, AuthorityKeyIdentifier, CertificateRevocationList, CRLDistributionPoints, IssuingDistributionPoint, BasicConstraints } from 'pkijs';
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
    CERTIFICATE_MISSING: 'certificate_missing',
    CERTIFICATE_AKI_MISSING: 'certificate_aki_missing',
    CERTIFICATE_NOT_YET_VALID: 'certificate_not_yet_valid',
    CERTIFICATE_EXPIRED: 'certificate_expired',
    CERTIFICATE_REVOKED: 'certificate_revoked',
    REVOCATION_STATUS_UNDETERMINED: 'revocation_status_undetermined',
    ISSUER_FETCH_FAILED: 'issuer_fetch_failed',
    ISSUER_CERTIFICATE_NOT_FOUND: 'issuer_certificate_not_found',
    CERTIFICATE_SIGNATURE_VERIFICATION_FAILED: 'certificate_signature_verification_failed',
    ISSUER_CERTIFICATE_NOT_YET_VALID: 'issuer_certificate_not_yet_valid',
    ISSUER_CERTIFICATE_EXPIRED: 'issuer_certificate_expired',
    ISSUER_CERTIFICATE_NOT_IN_TRUST_LISTS: 'issuer_certificate_not_in_trust_lists',
    ISSUER_MISSING_REQUIRED_TRUST_SCOPE: 'issuer_missing_required_trust_scope',
};

const deepCopy = (value) => JSON.parse(JSON.stringify(value));

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
const AUTHORITY_KEY_IDENTIFIER_OID = '2.5.29.35';
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

const normalizeCertificate = (certificate) => {
    if(certificate instanceof Certificate) return certificate;
    // Bundled consumers may have a separate copy of PKIjs with different class identities.
    return parsePemCertificate(typeof certificate === 'string' ? certificate : certificateToPem(certificate));
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

const getAuthorityKeyIdentifier = (x509Cert) => {
    const extension = x509Cert.extensions?.find(ext => ext.extnID === AUTHORITY_KEY_IDENTIFIER_OID);
    if(!extension) return null;

    try {
        const authorityKeyIdentifier = extension.parsedValue || new AuthorityKeyIdentifier({
            schema: asn1js.fromBER(extension.extnValue.valueBlock.valueHex).result,
        });
        const bytes = authorityKeyIdentifier.keyIdentifier?.valueBlock.valueHexView;
        return bytes?.byteLength ? bufferToBase64Url(bytes) : null;
    } catch(error) {
        return null;
    }
};

const isCertificateNotYetValid = (certificate, now = new Date()) => certificate.notBefore.value > now;

const isCertificateExpired = (certificate, now = new Date()) => certificate.notAfter.value < now;

const ensurePKIjsCryptoEngine = () => {
    try {
        getCrypto(true);
    } catch(error) {
        if(!globalThis.crypto?.subtle) throw error;
        setEngine('webcrypto', new CryptoEngine({ name: 'webcrypto', crypto: globalThis.crypto }));
    }
};

const verifyCertificateSignature = async (certificate, issuerCertificate) => {
    certificate = normalizeCertificate(certificate);
    issuerCertificate = normalizeCertificate(issuerCertificate);
    if(!certificate.issuer.isEqual(issuerCertificate.subject)) return false;
    ensurePKIjsCryptoEngine();
    try {
        return await certificate.verify(issuerCertificate);
    } catch(error) {
        return false;
    }
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

const getIssuerFromX509AKI = async (x509aki, options) => {
    const userTrustedIssuer = options.userTrustedIssuers[x509aki];
    const registryIssuer = await getRegistryIssuerFromX509AKI(x509aki, options);
    return userTrustedIssuer
        ? mergeIssuers(userTrustedIssuer, registryIssuer)
        : registryIssuer;
};

const getRegistryIssuerFromX509AKI = async (x509aki, options) => {
    const { cachedFetcher } = options;
    const url = `${REGISTRY_URL_BASE}/issuers/x509_aki/${x509aki}.json`;
    const response = await cachedFetcher.fetch(url, 'issuer');
    if(!response.ok && response.status !== 404) {
        throw new Error(`Failed to fetch issuer ${x509aki}: ${response.status} ${response.statusText || ''}`.trim());
    }
    return deepCopy(response.issuer);
};

const mergeIssuers = (userTrustedIssuer, registryIssuer) => {
    if(!userTrustedIssuer && !registryIssuer) return null;

    const issuer = {
        ...deepCopy(registryIssuer || {}),
        ...deepCopy(userTrustedIssuer || {}),
        entity_metadata: { ...registryIssuer?.entity_metadata, ...userTrustedIssuer?.entity_metadata },
        display: { ...registryIssuer?.display, ...userTrustedIssuer?.display },
        trust_scopes: [...new Set([
            ...userTrustedIssuer?.trust_scopes || [],
            ...registryIssuer?.trust_scopes || [],
        ])],
        certificates: [],
    };
    // Merged metadata and trust results are not covered by the registry signature.
    delete issuer.signature;

    const certificatesByPem = new Map();
    for(const certificate of [...userTrustedIssuer?.certificates || [], ...registryIssuer?.certificates || []]) {
        const existingCertificate = certificatesByPem.get(certificate.data);
        if(existingCertificate) {
            existingCertificate.trust_lists = [...new Set([...existingCertificate.trust_lists, ...certificate.trust_lists])];
        } else {
            const copy = deepCopy(certificate);
            copy.trust_lists = [...new Set(copy.trust_lists)];
            certificatesByPem.set(copy.data, copy);
            issuer.certificates.push(copy);
        }
    }
    return issuer;
};

const buildUserTrustedIssuers = (trustedIssuerCertificates = []) => {
    if(!Array.isArray(trustedIssuerCertificates)) {
        throw new Error('trustedIssuerCertificates must be an array');
    }

    const userTrustedIssuers = Object.create(null);
    for(const trustedIssuerCertificate of trustedIssuerCertificates) {
        const { subjectKeyIdentifier, issuer } = normalizeTrustedIssuerCertificate(trustedIssuerCertificate);
        const existingIssuer = userTrustedIssuers[subjectKeyIdentifier];
        if(existingIssuer) {
            userTrustedIssuers[subjectKeyIdentifier] = mergeIssuers(existingIssuer, issuer);
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

const verifyIssuer = async (issuer) => {
    const { signature, ...issuerData } = issuer;
    try {
        const data = new TextEncoder().encode(stringify(issuerData)).buffer;
        return await verifySignatureWithPem(PUBLIC_SIGNING_CERT, signature, data);
    } catch(error) {
        console.error('Issuer signature verification failed', error);
        return false;
    }
};

const BASIC_CONSTRAINTS_OID = '2.5.29.19';
const KEY_USAGE_OID = '2.5.29.15';
const CRL_REASON_OID = '2.5.29.21';
const DELTA_CRL_INDICATOR_OID = '2.5.29.27';
const ISSUING_DISTRIBUTION_POINT_OID = '2.5.29.28';
const CRL_DISTRIBUTION_POINTS_OID = '2.5.29.31';
const CRL_PEM_BEGIN = '-----BEGIN X509 CRL-----';
const CRL_PEM_END = '-----END X509 CRL-----';
const ALL_REASONS_MASK = 0x1FE;
const CRL_SIGN_KEY_USAGE_MASK = 0x02;
const REMOVE_FROM_CRL_REASON = 8;

const getCRLDistributionPoints = (certificate) => {
    const extension = certificate?.extensions?.find(ext => ext.extnID === CRL_DISTRIBUTION_POINTS_OID);
    if(!extension) return [];

    const crlDistributionPoints = parseExtensionValue(
        extension,
        CRLDistributionPoints,
        'Unable to parse CRL Distribution Points'
    );

    return crlDistributionPoints.distributionPoints
        .map(distributionPoint => ({
            distributionPoint: distributionPoint,
            urls: getDistributionPointUrls(distributionPoint),
        }))
        .filter(distributionPoint => distributionPoint.urls.length > 0);
};

const checkCertificateRevocation = async (certificate, issuerCertificate, { cachedFetcher }) => {
    let distributionPoints;
    try {
        distributionPoints = getCRLDistributionPoints(certificate);
    } catch(error) {
        return {
            checked: false,
            revoked: false,
            error: error.message,
        };
    }

    const urls = getAllDistributionPointUrls(distributionPoints);
    const result = {
        checked: false,
        revoked: false,
    };

    if(urls.length === 0) return result;

    const errors = [];
    const supportedDistributionPoints = [];
    for(const distributionPoint of distributionPoints) {
        if(hasDelegatedCRLIssuer(distributionPoint)) {
            errors.push('Delegated CRL issuers are not supported');
        } else {
            supportedDistributionPoints.push(distributionPoint);
        }
    }

    const supportedUrls = getAllDistributionPointUrls(supportedDistributionPoints);
    if(supportedUrls.length === 0) {
        if(errors.length > 0) result.error = errors.join('; ');
        return result;
    }

    let crlIssuerCertificate;
    try {
        crlIssuerCertificate = getIssuerCertificate(issuerCertificate);
        validateCRLIssuerCertificate(crlIssuerCertificate);
    } catch(error) {
        result.error = error.message;
        return result;
    }

    const evaluationState = {
        coveredReasonsMask: 0,
        errors: errors,
    };
    const pendingResultsByUrl = getPendingCRLResultsByUrl(supportedUrls, cachedFetcher);

    while(pendingResultsByUrl.size > 0) {
        const crlResult = await getNextCRLResult(pendingResultsByUrl);
        const revocationResult = await evaluateCRLResult(crlResult, supportedDistributionPoints, certificate, crlIssuerCertificate, evaluationState);
        if(revocationResult) {
            return revocationResult;
        }
    }

    if(evaluationState.coveredReasonsMask > 0 && !isCompleteCRLCoverage(evaluationState.coveredReasonsMask)) {
        evaluationState.errors.push('CRL coverage is incomplete');
    }

    if(evaluationState.errors.length > 0) result.error = evaluationState.errors.join('; ');
    return result;
};

const getPendingCRLResultsByUrl = (urls, cachedFetcher) => {
    const pendingResultsByUrl = new Map();

    for(const url of urls) {
        pendingResultsByUrl.set(url, fetchCRL(url, cachedFetcher)
            .then(crl => ({
                url: url,
                crl: crl,
            }))
            .catch(error => ({ url: url, error: error })));
    }

    return pendingResultsByUrl;
};

const getNextCRLResult = async (pendingResultsByUrl) => {
    const result = await Promise.race(pendingResultsByUrl.values());
    pendingResultsByUrl.delete(result.url);
    return result;
};

const evaluateCRLResult = async (crlResult, distributionPoints, certificate, crlIssuerCertificate, state) => {
    const {
        url,
        crl,
        error,
    } = crlResult;

    if(error) {
        state.errors.push(error.message);
        return null;
    }

    try {
        ensurePKIjsCryptoEngine();
        const signatureValid = await crl.verify({
            issuerCertificate: crlIssuerCertificate,
        });
        if(!signatureValid) {
            state.errors.push(`Invalid CRL signature for ${url}`);
            return null;
        }

        const matchingDistributionPoints = distributionPoints.filter(distributionPoint => distributionPoint.urls.includes(url));
        for(const distributionPoint of matchingDistributionPoints) {
            const coverage = getCRLCoverage(certificate, crl, distributionPoint.distributionPoint);
            if(!coverage.coversCertificate) {
                state.errors.push(`${coverage.error} for ${url}`);
                continue;
            }

            if(isCRLNotYetValid(crl)) {
                state.errors.push(`CRL is not yet valid for ${url}`);
                continue;
            }

            const stale = isCRLStale(crl);

            const revokedCertificate = crl.revokedCertificates?.find(entry => entry.userCertificate.isEqual(certificate.serialNumber));
            if(revokedCertificate) {
                if(getCRLEntryReason(revokedCertificate) !== REMOVE_FROM_CRL_REASON) {
                    return {
                        checked: true,
                        revoked: true,
                    };
                }
                if(!isDeltaCRL(crl)) {
                    state.errors.push(`removeFromCRL is only valid in a delta CRL for ${url}`);
                    continue;
                }
            }

            if(isDeltaCRL(crl)) {
                state.errors.push(`Delta CRL cannot establish non-revoked status for ${url}`);
                continue;
            }

            if(!stale) {
                state.coveredReasonsMask |= coverage.reasonsMask;
                if(isCompleteCRLCoverage(state.coveredReasonsMask)) {
                    return {
                        checked: true,
                        revoked: false,
                    };
                }
                continue;
            }

            state.errors.push(`CRL is stale for ${url}`);
        }
    } catch(error) {
        state.errors.push(error.message);
    }

    return null;
};

const getCRLEntryReason = (entry) => {
    const extension = entry.crlEntryExtensions?.extensions.find(ext => ext.extnID === CRL_REASON_OID);
    if(!extension) return null;

    const asn1 = asn1js.fromBER(extension.extnValue.valueBlock.valueHex);
    if(asn1.offset === -1 || !(asn1.result instanceof asn1js.Enumerated)) {
        throw new Error('Unable to parse CRL reason code');
    }
    return asn1.result.valueBlock.valueDec;
};

const getDistributionPointUrls = (distributionPoint) => {
    if(!Array.isArray(distributionPoint.distributionPoint)) return [];

    const urls = [];
    for(const generalName of distributionPoint.distributionPoint) {
        if(generalName.type === 6 && typeof generalName.value === 'string') {
            urls.push(generalName.value);
        }
    }
    return [...new Set(urls)];
};

const hasDelegatedCRLIssuer = (distributionPoint) => {
    return distributionPoint.distributionPoint.cRLIssuer?.length > 0;
};

const getAllDistributionPointUrls = (distributionPoints) => {
    const urls = [];
    for(const distributionPoint of distributionPoints) {
        urls.push(...distributionPoint.urls);
    }
    return [...new Set(urls)];
};

const getIssuerCertificate = (issuerCertificate) => {
    if(issuerCertificate instanceof Certificate) return issuerCertificate;
    if(issuerCertificate?.parsedCertificate instanceof Certificate) return issuerCertificate.parsedCertificate;
    if(typeof issuerCertificate === 'string') return parsePemCertificate(issuerCertificate);
    if(typeof issuerCertificate?.data === 'string') return parsePemCertificate(issuerCertificate.data);
    throw new Error('Issuer certificate is required to verify CRL signature');
};

const validateCRLIssuerCertificate = (issuerCertificate) => {
    if(issuerCertificate.version !== 2) return;

    const keyUsage = issuerCertificate.extensions?.find(ext => ext.extnID === KEY_USAGE_OID);
    if(!keyUsage) throw new Error('CRL issuer certificate key usage does not allow CRL signing');

    const keyUsageValue = asn1js.fromBER(keyUsage.extnValue.valueBlock.valueHex);
    if(keyUsageValue.offset === -1) throw new Error('Unable to parse CRL issuer certificate key usage');

    const keyUsageBytes = new Uint8Array(keyUsageValue.result.valueBlock.valueHexView || keyUsageValue.result.valueBlock.valueHex || []);
    if(!(keyUsageBytes[0] & CRL_SIGN_KEY_USAGE_MASK)) {
        throw new Error('CRL issuer certificate key usage does not allow CRL signing');
    }
};

const getCRLCoverage = (certificate, crl, distributionPoint) => {
    if(!crl.issuer.isEqual(certificate.issuer)) {
        return {
            coversCertificate: false,
            error: 'CRL issuer does not match certificate issuer',
        };
    }

    const issuingDistributionPoint = getIssuingDistributionPoint(crl);
    const issuingDistributionPointCoverage = getIssuingDistributionPointCoverage(
        certificate,
        issuingDistributionPoint,
        distributionPoint
    );
    if(!issuingDistributionPointCoverage.coversCertificate) return issuingDistributionPointCoverage;

    const distributionPointReasons = getReasonMask(distributionPoint.reasons);
    const crlReasons = issuingDistributionPoint?.onlySomeReasons === undefined
        ? ALL_REASONS_MASK
        : getReasonMaskFromBytes(new Uint8Array([issuingDistributionPoint.onlySomeReasons]));
    const reasonsMask = distributionPointReasons & crlReasons;

    if(reasonsMask === 0) {
        return {
            coversCertificate: false,
            error: 'CRL reason scope does not cover certificate distribution point',
        };
    }

    return {
        coversCertificate: true,
        reasonsMask: reasonsMask,
    };
};

const getIssuingDistributionPointCoverage = (certificate, issuingDistributionPoint, distributionPoint) => {
    if(!issuingDistributionPoint) {
        return {
            coversCertificate: true,
        };
    }

    if(issuingDistributionPoint.indirectCRL) {
        return {
            coversCertificate: false,
            error: 'Indirect CRLs are not supported',
        };
    }

    if(issuingDistributionPoint.onlyContainsAttributeCerts) {
        return {
            coversCertificate: false,
            error: 'CRL only covers attribute certificates',
        };
    }

    const certificateIsCA = isCertificateCA(certificate);
    if(issuingDistributionPoint.onlyContainsCACerts && !certificateIsCA) {
        return {
            coversCertificate: false,
            error: 'CRL only covers CA certificates',
        };
    }

    if(issuingDistributionPoint.onlyContainsUserCerts && certificateIsCA) {
        return {
            coversCertificate: false,
            error: 'CRL only covers user certificates',
        };
    }

    if(issuingDistributionPoint.distributionPoint) {
        const crlDistributionPointNames = getDistributionPointNameKeys(issuingDistributionPoint.distributionPoint);
        const certificateDistributionPointNames = getDistributionPointNameKeys(distributionPoint.distributionPoint);
        if(!hasSharedName(crlDistributionPointNames, certificateDistributionPointNames)) {
            return {
                coversCertificate: false,
                error: 'CRL distribution point scope does not match certificate distribution point',
            };
        }
    }

    return {
        coversCertificate: true,
    };
};

const getIssuingDistributionPoint = (crl) => {
    const extension = crl.crlExtensions?.extensions?.find(ext => ext.extnID === ISSUING_DISTRIBUTION_POINT_OID);
    if(!extension) return null;
    return parseExtensionValue(
        extension,
        IssuingDistributionPoint,
        'Unable to parse Issuing Distribution Point'
    );
};

const getReasonMask = (reasons) => {
    if(!reasons) return ALL_REASONS_MASK;
    const bytes = new Uint8Array(reasons.valueBlock.valueHexView || reasons.valueBlock.valueHex || []);
    return getReasonMaskFromBytes(bytes);
};

const getReasonMaskFromBytes = (bytes) => {
    let mask = 0;
    for(let byteIndex = 0; byteIndex < bytes.length; byteIndex++) {
        for(let bitIndex = 0; bitIndex < 8; bitIndex++) {
            if(bytes[byteIndex] & (0x80 >> bitIndex)) {
                mask |= 1 << ((byteIndex * 8) + bitIndex);
            }
        }
    }
    return mask & ALL_REASONS_MASK;
};

const isCompleteCRLCoverage = (reasonsMask) => {
    return (reasonsMask & ALL_REASONS_MASK) === ALL_REASONS_MASK;
};

const isCertificateCA = (certificate) => {
    const extension = certificate?.extensions?.find(ext => ext.extnID === BASIC_CONSTRAINTS_OID);
    if(!extension) return false;

    try {
        const basicConstraints = parseExtensionValue(
            extension,
            BasicConstraints,
            'Unable to parse Basic Constraints'
        );
        return !!basicConstraints.cA;
    } catch(error) {
        return false;
    }
};

const getDistributionPointNameKeys = (distributionPointName) => {
    if(!distributionPointName) return [];
    if(Array.isArray(distributionPointName)) {
        return distributionPointName
            .map(generalName => getGeneralNameKey(generalName));
    }
    if(typeof distributionPointName.toSchema === 'function') {
        return [`rdn:${bufferToHex(distributionPointName.toSchema().toBER(false))}`];
    }
    return [JSON.stringify(distributionPointName)];
};

const getGeneralNameKey = (generalName) => {
    if(generalName?.type === 6 && typeof generalName.value === 'string') {
        return `uri:${generalName.value}`;
    }
    if(typeof generalName?.toSchema === 'function') {
        return `asn1:${bufferToHex(generalName.toSchema().toBER(false))}`;
    }
    return JSON.stringify(generalName);
};

const hasSharedName = (firstNames, secondNames) => {
    if(firstNames.length === 0 || secondNames.length === 0) return false;
    const secondNameSet = new Set(secondNames);
    return firstNames.some(name => secondNameSet.has(name));
};

const bufferToHex = (buffer) => {
    return Array.from(new Uint8Array(buffer), byte => byte.toString(16).padStart(2, '0')).join('');
};

const parseExtensionValue = (extension, ExtensionValue, errorMessage) => {
    if(extension.parsedValue instanceof ExtensionValue) return extension.parsedValue;

    const asn1 = asn1js.fromBER(extension.extnValue.valueBlock.valueHex);
    if(asn1.offset === -1) throw new Error(errorMessage);
    return new ExtensionValue({ schema: asn1.result });
};

const isCRLNotYetValid = (crl) => {
    return crl.thisUpdate.value > new Date();
};

const isCRLStale = (crl) => {
    return !!crl.nextUpdate && crl.nextUpdate.value < new Date();
};

const isDeltaCRL = (crl) => {
    return !!crl.crlExtensions?.extensions?.some(ext => ext.extnID === DELTA_CRL_INDICATOR_OID);
};

const fetchCRL = async (url, cachedFetcher) => {
    const response = await cachedFetcher.fetch(url, 'crl');
    if(!response.ok) {
        throw new Error(`CRL request failed with HTTP ${response.status}`);
    }
    if(response.error) throw new Error(response.error);
    return response.crl;
};

const parseCRL = (bytes) => {
    const textPrefix = new TextDecoder().decode(bytes.slice(0, CRL_PEM_BEGIN.length + 20));
    const crlBytes = textPrefix.trimStart().startsWith(CRL_PEM_BEGIN)
        ? pemCRLToBytes(new TextDecoder().decode(bytes))
        : bytes;
    const arrayBuffer = crlBytes.buffer.slice(crlBytes.byteOffset, crlBytes.byteOffset + crlBytes.byteLength);
    const asn1 = asn1js.fromBER(arrayBuffer);
    if(asn1.offset === -1) throw new Error('Unable to parse CRL');
    return new CertificateRevocationList({ schema: asn1.result });
};

const pemCRLToBytes = (pem) => {
    const start = pem.indexOf(CRL_PEM_BEGIN);
    const end = pem.indexOf(CRL_PEM_END);
    if(start === -1 || end === -1) throw new Error('Unable to parse PEM CRL');
    const base64 = pem.slice(start + CRL_PEM_BEGIN.length, end).replace(/\s/g, '');
    return base64ToUint8Array(base64);
};

const resolveCertificateTrust = async (certificate, options) => {
    if(!certificate) return { trusted: false, untrustedReasons: [UntrustedReason.CERTIFICATE_MISSING] };
    certificate = normalizeCertificate(certificate);

    const x509aki = getAuthorityKeyIdentifier(certificate);
    if(!x509aki) return { trusted: false, untrustedReasons: [UntrustedReason.CERTIFICATE_AKI_MISSING] };

    const { trustLists = [], trustScope, userTrustedIssuers, cachedFetcher, revocationCheckMode } = options;
    const untrustedReasons = [];
    const now = new Date();
    if(isCertificateNotYetValid(certificate, now)) untrustedReasons.push(UntrustedReason.CERTIFICATE_NOT_YET_VALID);
    if(isCertificateExpired(certificate, now)) untrustedReasons.push(UntrustedReason.CERTIFICATE_EXPIRED);

    let registryIssuer = null;
    let registryFetchFailed = false;
    if(trustLists.length > 0) {
        try {
            registryIssuer = await getRegistryIssuerFromX509AKI(x509aki, { cachedFetcher });
        } catch(error) {
            registryFetchFailed = true;
        }
    }

    const issuer = mergeIssuers(userTrustedIssuers[x509aki], registryIssuer);
    let selectedCertificate = null;
    if(issuer) {
        issuer.certificates = await Promise.all(issuer.certificates.map(issuerCertificate => evaluateIssuerCertificate(
            certificate, issuerCertificate, issuer.trust_scopes, { trustLists, trustScope, cachedFetcher, revocationCheckMode, now }
        )));
        for(const issuerCertificate of issuer.certificates) {
            if(!selectedCertificate || (issuerCertificate.untrustedReasons?.length || 0) < (selectedCertificate.untrustedReasons?.length || 0)) {
                selectedCertificate = issuerCertificate;
            }
        }
    }

    if(selectedCertificate) {
        untrustedReasons.push(...selectedCertificate.untrustedReasons || []);
    } else {
        untrustedReasons.push(UntrustedReason.ISSUER_CERTIFICATE_NOT_FOUND);
    }
    if(registryFetchFailed && !selectedCertificate?.trusted) {
        untrustedReasons.push(UntrustedReason.ISSUER_FETCH_FAILED);
    }

    return {
        trusted: untrustedReasons.length === 0,
        ...(issuer && { issuer }),
        ...(untrustedReasons.length > 0 && { untrustedReasons }),
    };
};

const evaluateIssuerCertificate = async (certificate, issuerCertificate, trustScopes, options) => {
    const { trustLists, trustScope, cachedFetcher, revocationCheckMode, now } = options;
    const parsedIssuerCertificate = parsePemCertificate(issuerCertificate.data);
    const untrustedReasons = [];
    if(isCertificateNotYetValid(parsedIssuerCertificate, now)) untrustedReasons.push(UntrustedReason.ISSUER_CERTIFICATE_NOT_YET_VALID);
    if(isCertificateExpired(parsedIssuerCertificate, now)) untrustedReasons.push(UntrustedReason.ISSUER_CERTIFICATE_EXPIRED);
    if(!issuerCertificate.trust_lists.includes('user_provided') && !issuerCertificate.trust_lists.some(trustList => trustLists.includes(trustList))) {
        untrustedReasons.push(UntrustedReason.ISSUER_CERTIFICATE_NOT_IN_TRUST_LISTS);
    }
    if(trustScope != null && !trustScopes.includes(trustScope)) {
        untrustedReasons.push(UntrustedReason.ISSUER_MISSING_REQUIRED_TRUST_SCOPE);
    }

    let revocationStatus = 'not_checked';
    const signatureValid = await verifyCertificateSignature(certificate, parsedIssuerCertificate);
    if(!signatureValid) {
        untrustedReasons.push(UntrustedReason.CERTIFICATE_SIGNATURE_VERIFICATION_FAILED);
    } else if(revocationCheckMode !== RevocationCheckMode.SKIP) {
        const revocation = await checkCertificateRevocation(certificate, parsedIssuerCertificate, { cachedFetcher });
        if(revocation.revoked) {
            revocationStatus = 'revoked';
            untrustedReasons.push(UntrustedReason.CERTIFICATE_REVOKED);
        } else if(revocation.checked) {
            revocationStatus = 'not_revoked';
        } else if(revocationCheckMode === RevocationCheckMode.REQUIRED) {
            untrustedReasons.push(UntrustedReason.REVOCATION_STATUS_UNDETERMINED);
        }
    }

    return {
        ...issuerCertificate,
        trusted: untrustedReasons.length === 0,
        revocationStatus,
        ...(untrustedReasons.length > 0 && { untrustedReasons }),
    };
};

const MAX_CACHE_ENTRIES = 1024;
const CACHE_SWEEP_INTERVAL = 60 * 1000;

class CachedFetcher {
    constructor(options = {}) {
        this.cacheEnabled = options.cacheEnabled ?? true;
        this._cacheTTL = options.cacheTTL ?? 1000 * 60 * 60 * 24;
        this._timeout = options.timeout ?? 10000;
        this._cache = new Map();
        this._inFlight = new Map();
        this._lastCacheSweepAt = Date.now();
    }

    async fetch(url, purpose) {
        const cached = this._get(purpose, url);
        if(cached !== undefined) return cached;

        const response = await this._fetch(url);
        switch(purpose) {
            case 'issuer': return this._cacheIssuerResponse(url, response);
            case 'deprecation': return this._cacheDeprecationResponse(url, response);
            case 'crl': return this._cacheCRLResponse(url, response);
            default: throw new Error(`Unsupported fetch purpose: ${purpose}`);
        }
    }

    _get(purpose, url) {
        if(!this.cacheEnabled) return undefined;
        const now = Date.now();
        this._sweepExpiredEntries(now);
        const key = `${purpose}:${url}`;
        const cached = this._cache.get(key);
        if(!cached) return undefined;
        if(cached.expiresAt <= now) {
            this._cache.delete(key);
            return undefined;
        }
        this._cache.delete(key);
        this._cache.set(key, cached);
        return cached.value;
    }

    _set(purpose, url, value, options = {}) {
        if(!this.cacheEnabled) return;
        const now = Date.now();
        this._sweepExpiredEntries(now);
        const expiresAt = Math.min(now + this._cacheTTL, options.expiresAt ?? Infinity);
        const key = `${purpose}:${url}`;
        if(expiresAt <= now) {
            this._cache.delete(key);
            return;
        }
        this._cache.delete(key);
        this._cache.set(key, { value, expiresAt });
        if(this._cache.size > MAX_CACHE_ENTRIES) {
            this._cache.delete(this._cache.keys().next().value);
        }
    }

    _sweepExpiredEntries(now) {
        if(now - this._lastCacheSweepAt < CACHE_SWEEP_INTERVAL) return;
        this._lastCacheSweepAt = now;
        for(const [key, cached] of this._cache) {
            if(cached.expiresAt <= now) this._cache.delete(key);
        }
    }

    async _cacheIssuerResponse(url, { bytes, ...result }) {
        result.issuer = null;
        if(result.ok) {
            const issuer = JSON.parse(new TextDecoder().decode(bytes));
            if(await verifyIssuer(issuer)) result.issuer = issuer;
        }
        if(result.issuer || result.status === 404) this._set('issuer', url, result);
        return result;
    }

    _cacheDeprecationResponse(url, { bytes, ...result }) {
        if(result.ok) {
            try {
                result.deprecationNotice = JSON.parse(new TextDecoder().decode(bytes));
            } catch(error) {
                result.error = error.message;
            }
        }
        if(result.ok || result.status === 404) this._set('deprecation', url, result);
        return result;
    }

    _cacheCRLResponse(url, { bytes, ...result }) {
        if(result.ok) {
            try {
                result.crl = parseCRL(bytes);
            } catch(error) {
                // A completed download is reusable even when its contents are malformed.
                result.error = error.message;
            }
        }
        const nextUpdate = result.crl?.nextUpdate?.value.getTime();
        if(result.ok || result.status === 404) {
            this._set('crl', url, result, {
                expiresAt: nextUpdate > Date.now() ? nextUpdate : undefined,
            });
        }
        return result;
    }

    async _fetch(url) {
        let request = this._inFlight.get(url);
        if(!request) {
            const controller = new AbortController();
            request = { controller, consumers: 0 };
            request.promise = this._download(url, controller.signal).finally(() => {
                if(this._inFlight.get(url) === request) this._inFlight.delete(url);
            });
            this._inFlight.set(url, request);
        }

        request.consumers++;
        let timeoutId;
        try {
            return await Promise.race([
                request.promise,
                new Promise((_resolve, reject) => {
                    timeoutId = setTimeout(() => {
                        const error = new Error(`Request timed out after ${this._timeout}ms`);
                        error.name = 'TimeoutError';
                        reject(error);
                    }, this._timeout);
                }),
            ]);
        } finally {
            clearTimeout(timeoutId);
            request.consumers--;
            // A caller's timeout must not cancel other callers sharing the download.
            if(request.consumers === 0 && this._inFlight.get(url) === request) {
                this._inFlight.delete(url);
                request.controller.abort();
            }
        }
    }

    async _download(url, signal) {
        const response = await fetch(url, { signal });
        const bytes = response.ok ? new Uint8Array(await response.arrayBuffer()) : null;
        if(!response.ok) await response.body?.cancel();
        return {
            ok: response.ok,
            status: response.status,
            statusText: response.statusText || '',
            bytes,
        };
    }
}

class Registry {
    constructor(options = {}) {
        this._cachedFetcher = new CachedFetcher(options);
        this._revocationCheckMode = normalizeRevocationCheckMode(options.revocationCheckMode);
        this._userTrustedIssuers = buildUserTrustedIssuers(options.trustedIssuerCertificates ?? []);
    }

    async getEndOfLifeDate() {
        const url = `${REGISTRY_URL_BASE}/deprecation_notice.json`;
        const response = await this._cachedFetcher.fetch(url, 'deprecation');
        let endOfLifeDate = null;
        if (response.ok) {
            if(response.error) throw new SyntaxError(response.error);
            const deprecationNotice = response.deprecationNotice;
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

        return endOfLifeDate;
    }

    async getIssuerFromX509AKI(x509aki) {
        return getIssuerFromX509AKI(x509aki, {
            userTrustedIssuers: this._userTrustedIssuers,
            cachedFetcher: this._cachedFetcher,
        });
    }

    async resolveCertificateTrust(certificate, options = {}) {
        return resolveCertificateTrust(certificate, {
            ...options,
            userTrustedIssuers: this._userTrustedIssuers,
            cachedFetcher: this._cachedFetcher,
            revocationCheckMode: this._revocationCheckMode,
        });
    }

    static minorVersion = MINOR_VERSION;
}

const normalizeRevocationCheckMode = (revocationCheckMode) => {
    const mode = revocationCheckMode ?? RevocationCheckMode.SKIP;
    if(!Object.values(RevocationCheckMode).includes(mode)) {
        throw new Error(`Unsupported CRL check mode: ${mode}`);
    }

    return mode;
};

export { Registry, RevocationCheckMode, TrustList, TrustScope, UntrustedReason, certificateToPem, parsePemCertificate, verifyCertificateSignature, verifySignatureWithPem };
