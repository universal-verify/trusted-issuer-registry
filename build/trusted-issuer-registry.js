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

function base64ToUint8Array(base64) {
    if(typeof Buffer == 'function') {
        return new Uint8Array(Buffer.from(base64, 'base64'));
    } else {
        const raw = atob(base64);
        const bytes = new Uint8Array(raw.length);
        for (let i = 0; i < raw.length; i++) {
            bytes[i] = raw.charCodeAt(i);
        }
        return bytes;
    }
}

// Helper to pad or trim a Uint8Array to a specific length
function padOrTrimUint8Array(buf, length) {
    if (buf.length === length) return buf;
    if (buf.length > length) return buf.slice(buf.length - length);
    // pad with zeros at the start
    const out = new Uint8Array(length);
    out.set(buf, length - buf.length);
    return out;
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

class TrustedIssuerRegistry {
    constructor(options = {}) {
        this._cacheEnabled = options.cacheEnabled ?? true;
        this._cacheTTL = options.cacheTTL ?? 1000 * 60 * 60 * 24; // 24 hours
        this._urlBase = REGISTRY_URL_BASE;
        this._cache = {};
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
        if (this._cacheEnabled && x509aki in this._cache && this._cache[x509aki].expiresAt > Date.now()) return this._deepCopy(this._cache[x509aki].issuer);

        const response = await fetch(`${this._urlBase}/issuers/x509_aki/${x509aki}.json`);
        if (response.ok) {
            const issuer = await response.json();
            const verified = await this._verifyIssuer(issuer);
            if (!verified) return null;
            if (this._cacheEnabled) {
                this._cache[x509aki] = {
                    issuer,
                    expiresAt: Date.now() + this._cacheTTL
                };
            }
            return this._deepCopy(issuer);
        } else if (response.status === 404) {
            if (this._cacheEnabled) {
                this._cache[x509aki] = {
                    issuer: null,
                    expiresAt: Date.now() + this._cacheTTL
                };
            }
        } else {
            throw new Error(`Failed to fetch issuer ${x509aki}: ${response.status} ${response.statusText || ''}`.trim());
        }

        return null;
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

//For CommonJS compatibility... boo CommonJS people, get with the times
TrustedIssuerRegistry.verifySignatureWithPem = verifySignatureWithPem;

export { TrustedIssuerRegistry as default, verifySignatureWithPem };
