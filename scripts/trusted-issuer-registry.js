import { REGISTRY_URL_BASE, MINOR_VERSION, RevocationCheckMode, TrustList, TrustScope, UntrustedReason } from './constants.js';
import { certificateToPem, parsePemCertificate, verifyCertificateSignature, verifySignatureWithPem } from './certificate-helper.js';
import { buildUserTrustedIssuers, getIssuerFromX509AKI } from './issuer-helper.js';
import { resolveCertificateTrust } from './trust-helper.js';
import { CachedFetcher } from './cached-fetcher.js';

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
