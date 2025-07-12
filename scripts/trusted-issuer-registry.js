import { REGISTRY_URL_BASE, ROOT_CA_CERTIFICATE, TEST_REGISTRY_URL_BASE } from './constants.js';
import { verifySignatureWithPem } from './certificate-helper.js';
import stringify from 'canonical-json';

class TrustedIssuerRegistry {
    constructor(options = {}) {
        this._cacheEnabled = options.cacheEnabled ?? true;
        this._cacheTTL = options.cacheTTL ?? 1000 * 60 * 60 * 24; // 24 hours
        this._urlBase = options.useTestData ? TEST_REGISTRY_URL_BASE : REGISTRY_URL_BASE;
        this._cache = {};
    }

    async getIssuerFromX509AKI(x509aki) {
        if (this._cacheEnabled && x509aki in this._cache && this._cache[x509aki].expiresAt > Date.now()) return this._cache[x509aki].issuer;

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
            return issuer;
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
            verified = await verifySignatureWithPem(ROOT_CA_CERTIFICATE, signature, issuerData);
        } catch (e) {
            console.error('Issuer signature verification failed', e);
        }
        return verified;
    }
}

//For CommonJS compatibility... boo CommonJS people, get with the times
TrustedIssuerRegistry.verifySignatureWithPem = verifySignatureWithPem;

export { verifySignatureWithPem };
export default TrustedIssuerRegistry;