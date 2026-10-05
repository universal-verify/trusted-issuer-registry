import { RevocationCheckMode, UntrustedReason } from './constants.js';
import {
    getAuthorityKeyIdentifier,
    isCertificateExpired,
    isCertificateNotYetValid,
    normalizeCertificate,
    parsePemCertificate,
    verifyCertificateSignature,
} from './certificate-helper.js';
import { checkCertificateRevocation } from './crl-helper.js';
import { getRegistryIssuerFromX509AKI, mergeIssuers } from './issuer-helper.js';

export const resolveCertificateTrust = async (certificate, options) => {
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
