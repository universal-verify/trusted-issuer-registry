import * as asn1js from 'asn1js';
import { AuthorityKeyIdentifier, Certificate, CryptoEngine, getCrypto, setEngine } from 'pkijs';
import {
    base64ToUint8Array,
    bufferToBase64Url,
    padOrTrimUint8Array,
    uint8ArrayToBase64,
} from './utils.js';

const SUBJECT_KEY_IDENTIFIER_OID = '2.5.29.14';
const AUTHORITY_KEY_IDENTIFIER_OID = '2.5.29.35';
const CRL_DISTRIBUTION_POINTS_OID = '2.5.29.31';
const SUBJECT_ATTRIBUTE_NAMES = {
    '2.5.4.3': 'commonName',
    '2.5.4.6': 'country',
    '2.5.4.7': 'locality',
    '2.5.4.8': 'state',
    '2.5.4.10': 'organization',
    '2.5.4.11': 'organizationalUnit',
};

export const parsePemCertificate = (pemString) => {
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

export const normalizeCertificate = (certificate) => {
    if(certificate instanceof Certificate) return certificate;
    // Bundled consumers may have a separate copy of PKIjs with different class identities.
    return parsePemCertificate(typeof certificate === 'string' ? certificate : certificateToPem(certificate));
};

export const certificateToPem = (x509Cert) => {
    const certBytes = new Uint8Array(x509Cert.toSchema().toBER());
    const base64 = uint8ArrayToBase64(certBytes);
    const pemLines = [];
    for (let i = 0; i < base64.length; i += 64) {
        pemLines.push(base64.slice(i, i + 64));
    }

    return `-----BEGIN CERTIFICATE-----\n${pemLines.join('\n')}\n-----END CERTIFICATE-----`;
};

export const getSubjectKeyIdentifier = (x509Cert) => {
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

export const getAuthorityKeyIdentifier = (x509Cert) => {
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

export const isCertificateNotYetValid = (certificate, now = new Date()) => certificate.notBefore.value > now;

export const isCertificateExpired = (certificate, now = new Date()) => certificate.notAfter.value < now;

export const ensurePKIjsCryptoEngine = () => {
    try {
        getCrypto(true);
    } catch(error) {
        if(!globalThis.crypto?.subtle) throw error;
        setEngine('webcrypto', new CryptoEngine({ name: 'webcrypto', crypto: globalThis.crypto }));
    }
};

export const verifyCertificateSignature = async (certificate, issuerCertificate) => {
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

export const getCertificateSubject = (x509Cert) => {
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

export const getCertificateDisplayName = (x509Cert) => {
    const subject = getCertificateSubject(x509Cert);
    return subject.organization || subject.commonName || null;
};

export const hasCRLDistributionPoints = (x509Cert) => {
    return !!x509Cert?.extensions?.some(ext => ext.extnID === CRL_DISTRIBUTION_POINTS_OID);
};

export const verifySignatureWithPem = async (pemKey, signature, data) => {
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
