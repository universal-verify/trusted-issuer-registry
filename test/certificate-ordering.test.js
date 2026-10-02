import test from 'node:test';
import assert from 'node:assert/strict';
import { createCertificateEntry, sortCertificateEntries } from '../scripts/utils/certificate-ordering.js';

function createCert(data, notBeforeMs, notAfterMs = 0) {
    return createCertificateEntry({ pemContent: data, notBeforeMs, notAfterMs }, 'uv');
}

test('sortCertificateEntries orders by newest notBefore first', () => {
    const older = createCert('older-pem', 1000);
    const newer = createCert('newer-pem', 2000);
    const certificates = [older, newer];

    sortCertificateEntries(certificates);

    assert.deepEqual(certificates.map(certificate => certificate.data), ['newer-pem', 'older-pem']);
});

test('sortCertificateEntries orders matching notBefore by latest notAfter', () => {
    const earlierExpiration = createCert('earlier-expiration-pem', 1000, 2000);
    const laterExpiration = createCert('later-expiration-pem', 1000, 3000);
    const certificates = [earlierExpiration, laterExpiration];

    sortCertificateEntries(certificates);

    assert.deepEqual(certificates.map(certificate => certificate.data), ['later-expiration-pem', 'earlier-expiration-pem']);
});

test('sortCertificateEntries uses PEM content when validity windows match', () => {
    const zCertificate = createCert('z-pem', 1000, 2000);
    const aCertificate = createCert('a-pem', 1000, 2000);
    const certificates = [zCertificate, aCertificate];

    sortCertificateEntries(certificates);

    assert.deepEqual(certificates.map(certificate => certificate.data), ['a-pem', 'z-pem']);
});

test('createCertificateEntry keeps ordering metadata out of published JSON', () => {
    const certificate = createCert('pem', 1000);

    assert.equal(JSON.stringify(certificate), '{"data":"pem","format":"pem","trust_lists":["uv"]}');
});
