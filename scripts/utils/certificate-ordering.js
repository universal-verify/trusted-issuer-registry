const issuedAt = Symbol('issuedAt');
const expiresAt = Symbol('expiresAt');

function createCertificateEntry(certInfo, trustList) {
    const certificate = {
        'data': certInfo.pemContent,
        'format': 'pem',
        'trust_lists': [trustList]
    };

    if (Number.isFinite(certInfo.notBeforeMs)) {
        Object.defineProperty(certificate, issuedAt, {
            value: certInfo.notBeforeMs,
            enumerable: false
        });
    }

    if (Number.isFinite(certInfo.notAfterMs)) {
        Object.defineProperty(certificate, expiresAt, {
            value: certInfo.notAfterMs,
            enumerable: false
        });
    }

    return certificate;
}

function sortCertificateEntries(certificates) {
    certificates.sort((a, b) => {
        const issuedAtDifference = (b[issuedAt] || 0) - (a[issuedAt] || 0);
        if (issuedAtDifference !== 0) return issuedAtDifference;

        const expiresAtDifference = (b[expiresAt] || 0) - (a[expiresAt] || 0);
        if (expiresAtDifference !== 0) return expiresAtDifference;

        if (a.data < b.data) return -1;
        if (a.data > b.data) return 1;
        return 0;
    });
}

export { createCertificateEntry, sortCertificateEntries };
