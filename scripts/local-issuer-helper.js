import {
    certificateToPem,
    getCertificateDisplayName,
    getCertificateSubject,
    getSubjectKeyIdentifier,
    parsePemCertificate,
} from './certificate-helper.js';

export const buildUserTrustedIssuers = (trustedIssuerCertificates = []) => {
    if(!Array.isArray(trustedIssuerCertificates)) {
        throw new Error('trustedIssuerCertificates must be an array');
    }

    const userTrustedIssuers = Object.create(null);
    for(const trustedIssuerCertificate of trustedIssuerCertificates) {
        const { subjectKeyIdentifier, issuer } = normalizeTrustedIssuerCertificate(trustedIssuerCertificate);
        const existingIssuer = userTrustedIssuers[subjectKeyIdentifier];
        if(existingIssuer) {
            existingIssuer.certificates.push(...issuer.certificates);
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
