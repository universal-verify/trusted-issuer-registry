import {
    certificateToPem,
    getCertificateSubject,
    getSubjectKeyIdentifier,
    hasCRLDistributionPoints,
    parsePemCertificate,
} from '../certificate-helper.js';

export default function extractCertificateInfo(pemContent) {
    try {
        const certificate = parsePemCertificate(pemContent);
        const subjectKeyIdentifier = getSubjectKeyIdentifier(certificate);
        if(!subjectKeyIdentifier) {
            throw new Error('Subject Key Identifier not found in certificate');
        }

        const notBeforeMs = getCertificateDateMs(certificate.notBefore?.value, 'Not Before');
        const notAfterMs = getCertificateDateMs(certificate.notAfter?.value, 'Not After');

        return {
            aki: subjectKeyIdentifier,
            subject: getCertificateSubject(certificate),
            pemContent: certificateToPem(certificate),
            notBeforeMs,
            notAfterMs,
            crlMissing: !hasCRLDistributionPoints(certificate),
        };
    } catch (error) {
        throw new Error(`Failed to extract certificate information: ${error.message}`);
    }
}

const getCertificateDateMs = (date, label) => {
    if(!(date instanceof Date) || !Number.isFinite(date.getTime())) {
        throw new Error(`${label} date not found in certificate`);
    }
    return date.getTime();
};
