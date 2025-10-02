import { REGISTRY_URL_BASE, PUBLIC_SIGNING_CERT, TEST_REGISTRY_URL_BASE, MINOR_VERSION } from './constants.js';
import { verifySignatureWithPem } from './certificate-helper.js';
import stringify from 'canonical-json';

class TrustedIssuerRegistry {
    constructor(options = {}) {
        this._cacheEnabled = options.cacheEnabled ?? true;
        this._cacheTTL = options.cacheTTL ?? 1000 * 60 * 60 * 24; // 24 hours
        this._urlBase = options.useTestData ? TEST_REGISTRY_URL_BASE : REGISTRY_URL_BASE;
        this._cache = {};
    }

    async getEndOfLifeDate() {
        const response = await fetch(`${this._urlBase}/deprecation_notice.json`);
        if (response.ok) {
            const deprecationNotice = await response.json();
            if(!deprecationNotice.version) return null;
            const [major, minor] = deprecationNotice.version.split('.').map(Number);
            const [currentMajor, currentMinor] = MINOR_VERSION.split('.').map(Number);
            if(major < currentMajor || (major === currentMajor && minor < currentMinor)) return null;
            return new Date(deprecationNotice.end_of_life * 1000);
        }
        return null;
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
        } else if (this._cacheEnabled) {
            this._cache[x509aki] = {
                issuer: null,
                expiresAt: Date.now() + this._cacheTTL
            };
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

    static minorVersion = MINOR_VERSION;
}

//For CommonJS compatibility... boo CommonJS people, get with the times
TrustedIssuerRegistry.verifySignatureWithPem = verifySignatureWithPem;

export { verifySignatureWithPem };
export default TrustedIssuerRegistry;
