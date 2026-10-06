import * as asn1js from 'asn1js';
import { AlgorithmIdentifier, AuthorityKeyIdentifier, Certificate, CryptoEngine, RSAPublicKey, RSASSAPSSParams, getCrypto, setEngine } from 'pkijs';
import {
    base64ToUint8Array,
    bufferToBase64Url,
    uint8ArrayToBase64,
} from './utils.js';

const SUBJECT_KEY_IDENTIFIER_OID = '2.5.29.14';
const AUTHORITY_KEY_IDENTIFIER_OID = '2.5.29.35';
const CRL_DISTRIBUTION_POINTS_OID = '2.5.29.31';
const RSA_PSS_OID = '1.2.840.113549.1.1.10';
const MGF1_OID = '1.2.840.113549.1.1.8';
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
    return Certificate.fromBER(bytes);
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

export const parseExtensionValue = (extension, ExtensionValue, errorMessage) => {
    const value = extension.parsedValue;
    const tag = ExtensionValue.prototype instanceof asn1js.BaseBlock ? new ExtensionValue().idBlock : null;
    const valid = tag
        ? value?.idBlock?.tagClass === tag.tagClass && value.idBlock.tagNumber === tag.tagNumber && !value.idBlock.isConstructed
        : value instanceof ExtensionValue;
    if(!valid || value.parsingError || value.error) throw new Error(errorMessage);
    return value;
};

export const getSubjectKeyIdentifier = (x509Cert) => {
    if(!x509Cert) return null;
    const subjectKeyId = x509Cert.extensions?.find(ext => ext.extnID === SUBJECT_KEY_IDENTIFIER_OID);
    if (!subjectKeyId) return null;

    try {
        const value = parseExtensionValue(subjectKeyId, asn1js.OctetString, 'Unable to parse Subject Key Identifier');
        const bytes = value.valueBlock.valueHexView;
        return bytes.byteLength ? bufferToBase64Url(bytes) : null;
    } catch (e) {
        console.error('Could not parse SubjectKeyIdentifier value', e);
    }
    return null;
};

export const getAuthorityKeyIdentifier = (x509Cert) => {
    const extension = x509Cert.extensions?.find(ext => ext.extnID === AUTHORITY_KEY_IDENTIFIER_OID);
    if(!extension) return null;

    try {
        const authorityKeyIdentifier = parseExtensionValue(extension, AuthorityKeyIdentifier, 'Unable to parse Authority Key Identifier');
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
    try {
        return await certificate.verify(issuerCertificate, { verifyWithPublicKey: verifySignedData });
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

export const verifySignatureWithPem = async (pemKey, signature, data, options = {}) => {
    try {
        const cert = parsePemCertificate(pemKey);
        const publicKeyInfo = cert.subjectPublicKeyInfo;
        if (!publicKeyInfo || !publicKeyInfo.algorithm || !publicKeyInfo.algorithm.algorithmId) {
            console.error('Parsed publicKeyInfo:', publicKeyInfo);
            throw new Error('Could not extract algorithm information from public key');
        }

        const webCryptoAlg = getWebCryptoAlgorithmFromOid(publicKeyInfo, options);
        ensurePKIjsCryptoEngine();
        const hash = typeof webCryptoAlg.hash === 'string' ? webCryptoAlg.hash : webCryptoAlg.hash.name;
        const cryptoEngine = getCrypto(true);
        const signatureAlgorithm = new AlgorithmIdentifier({
            algorithmId: cryptoEngine.getOIDByAlgorithm({ ...webCryptoAlg, hash: { name: hash } }, true),
        });
        if(webCryptoAlg.name === 'RSA-PSS') {
            const hashAlgorithm = new AlgorithmIdentifier({
                algorithmId: cryptoEngine.getOIDByAlgorithm({ name: hash }, true),
            });
            signatureAlgorithm.algorithmParams = new RSASSAPSSParams({
                hashAlgorithm,
                maskGenAlgorithm: new AlgorithmIdentifier({ algorithmId: MGF1_OID, algorithmParams: hashAlgorithm.toSchema() }),
                saltLength: webCryptoAlg.saltLength,
            }).toSchema();
        }
        return await verifySignedData(data, new asn1js.BitString({ valueHex: base64ToUint8Array(signature) }), publicKeyInfo, signatureAlgorithm);
    } catch (error) {
        console.error('Error verifying signature:', error);
        throw error;
    }
};

export const verifySignedData = async (data, signature, publicKeyInfo, signatureAlgorithm) => {
    ensurePKIjsCryptoEngine();
    const cryptoEngine = getCrypto(true);
    const algorithm = cryptoEngine.getAlgorithmByOID(signatureAlgorithm.algorithmId, true);
    if(algorithm.name === 'ECDSA') validateECDSASignature(signature.valueBlock.valueHexView);
    const pss = signatureAlgorithm.algorithmId === RSA_PSS_OID ? parsePSSParameters(signatureAlgorithm) : null;
    if(publicKeyInfo.algorithm.algorithmId === RSA_PSS_OID) {
        if(!pss) throw new Error('RSA-PSS certificates require the RSA-PSS signature algorithm');
        if(publicKeyInfo.algorithm.algorithmParams) {
            const restrictions = parsePSSParameters(publicKeyInfo.algorithm);
            if(pss.hashAlgorithm.algorithmId !== restrictions.hashAlgorithm.algorithmId || pss.saltLength < restrictions.saltLength) {
                throw new Error('Signature parameters do not satisfy RSA-PSS public key restrictions');
            }
        }
        // JWK import supports PSS-only keys without changing the original certificate.
        const rsa = RSAPublicKey.fromBER(publicKeyInfo.subjectPublicKey.valueBlock.valueHexView);
        const key = await cryptoEngine.importKey('jwk', { kty: 'RSA', ...rsa.toJSON() }, {
            name: 'RSA-PSS', hash: cryptoEngine.getHashAlgorithm(signatureAlgorithm),
        }, false, ['verify']);
        return cryptoEngine.verify({ name: 'RSA-PSS', saltLength: pss.saltLength }, key, signature.valueBlock.valueHexView, data);
    }
    return cryptoEngine.verifyWithPublicKey(data, signature, publicKeyInfo, signatureAlgorithm);
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

function validateECDSASignature(bytes) {
    const asn1 = asn1js.fromBER(bytes);
    if(asn1.offset === -1 || asn1.offset !== bytes.byteLength || !(asn1.result instanceof asn1js.Sequence)
        || asn1.result.valueBlock.value.length !== 2 || !asn1.result.valueBlock.value.every(value => value instanceof asn1js.Integer)) {
        throw new Error('Invalid DER signature structure');
    }
}

function parsePSSParameters(algorithm) {
    if(!algorithm.algorithmParams) throw new Error('RSA-PSS signature parameters are required');
    const parameters = new RSASSAPSSParams({ schema: algorithm.algorithmParams });
    const mgf = parameters.maskGenAlgorithm;
    if(mgf.algorithmId !== MGF1_OID || !mgf.algorithmParams || parameters.trailerField !== 1
        || !Number.isInteger(parameters.saltLength) || parameters.saltLength < 0) {
        throw new Error('Unsupported RSA-PSS parameters');
    }
    const mgfHash = new AlgorithmIdentifier({ schema: mgf.algorithmParams });
    if(mgfHash.algorithmId !== parameters.hashAlgorithm.algorithmId) {
        throw new Error('RSA-PSS MGF1 hash must match the signature hash');
    }
    return parameters;
}

function getWebCryptoAlgorithmFromOid(publicKeyInfo, options) {
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
            if(options.name !== undefined && options.name !== 'ECDSA') {
                throw new Error('EC certificates require the ECDSA signature algorithm');
            }
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
                    return { name: 'ECDSA', namedCurve: 'P-256', hash: options.hash ?? { name: 'SHA-256' } };
                case '1.3.132.0.34': // P-384
                    return { name: 'ECDSA', namedCurve: 'P-384', hash: options.hash ?? { name: 'SHA-384' } };
                case '1.3.132.0.35': // P-521
                    return { name: 'ECDSA', namedCurve: 'P-521', hash: options.hash ?? { name: 'SHA-512' } };
                case undefined:
                    // Default to P-256 if no parameters provided
                    return { name: 'ECDSA', namedCurve: 'P-256', hash: options.hash ?? { name: 'SHA-256' } };
                default:
                    throw new Error(`Unsupported EC curve: ${curveOid}`);
            }
        case '1.2.840.113549.1.1.1': // rsaEncryption
        case '1.2.840.113549.1.1.10': // rsassaPss
            if(!['RSASSA-PKCS1-v1_5', 'RSA-PSS'].includes(options.name) || !options.hash) {
                throw new Error('RSA signatures require explicit name and hash options');
            }
            if(oidString === '1.2.840.113549.1.1.10' && options.name !== 'RSA-PSS') {
                throw new Error('RSA-PSS certificates require the RSA-PSS signature algorithm');
            }
            if(options.name === 'RSA-PSS') {
                if(!Number.isInteger(options.saltLength) || options.saltLength < 0) {
                    throw new Error('RSA-PSS signatures require a non-negative integer saltLength');
                }
                return { name: options.name, hash: options.hash, saltLength: options.saltLength };
            }
            return { name: options.name, hash: options.hash };
        default:
            throw new Error(`Unsupported algorithm OID: ${oidString}`);
    }
}
