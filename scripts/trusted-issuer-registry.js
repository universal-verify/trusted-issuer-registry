import { REGISTRY_URL_BASE, PUBLIC_SIGNING_CERT, MINOR_VERSION } from './constants.js';
import { verifySignatureWithPem } from './certificate-helper.js';
import stringify from 'canonical-json';

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

export { verifySignatureWithPem };
export default TrustedIssuerRegistry;
