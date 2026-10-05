import {
    certificateToPem,
    getCertificateDisplayName,
    getCertificateSubject,
    getSubjectKeyIdentifier,
    parsePemCertificate,
    verifySignatureWithPem,
} from './certificate-helper.js';
import { PUBLIC_SIGNING_CERT, REGISTRY_URL_BASE } from './constants.js';
import { deepCopy } from './utils.js';
import stringify from 'canonical-json';

export const getIssuerFromX509AKI = async (x509aki, options) => {
    const userTrustedIssuer = options.userTrustedIssuers[x509aki];
    const registryIssuer = await getRegistryIssuerFromX509AKI(x509aki, options);
    return userTrustedIssuer
        ? mergeIssuers(userTrustedIssuer, registryIssuer)
        : registryIssuer;
};

export const getRegistryIssuerFromX509AKI = async (x509aki, options) => {
    const { cachedFetcher } = options;
    const url = `${REGISTRY_URL_BASE}/issuers/x509_aki/${x509aki}.json`;
    const response = await cachedFetcher.fetch(url, 'issuer');
    if(!response.ok && response.status !== 404) {
        throw new Error(`Failed to fetch issuer ${x509aki}: ${response.status} ${response.statusText || ''}`.trim());
    }
    return deepCopy(response.issuer);
};

export const mergeIssuers = (userTrustedIssuer, registryIssuer) => {
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

export const buildUserTrustedIssuers = (trustedIssuerCertificates = []) => {
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

export const verifyIssuer = async (issuer) => {
    const { signature, ...issuerData } = issuer;
    try {
        const data = new TextEncoder().encode(stringify(issuerData)).buffer;
        return await verifySignatureWithPem(PUBLIC_SIGNING_CERT, signature, data);
    } catch(error) {
        console.error('Issuer signature verification failed', error);
        return false;
    }
};
