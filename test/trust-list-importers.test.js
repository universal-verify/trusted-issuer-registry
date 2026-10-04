import test from 'node:test';
import assert from 'node:assert/strict';
import * as cbor2 from 'cbor2';
import fetchFromUV from '../scripts/utils/trust_lists/uv.js';
import fetchFromAAMVA from '../scripts/utils/trust_lists/aamva_dts.js';

const APPLE_ROOT_CERT_WITHOUT_CRL = `-----BEGIN CERTIFICATE-----
MIICazCCAfGgAwIBAgIQaoszpPsbgR517fbRv3ThWzAKBggqhkjOPQQDAzBVMQsw
CQYDVQQGEwJVUzETMBEGA1UECgwKQXBwbGUgSW5jLjExMC8GA1UEAwwoQXBwbGUg
SXNzdWluZyBBdXRob3JpdHkgRUNDIFJvb3QgQ0EgLSBHMTAeFw0yNTA0MjkyMTM2
MzRaFw00NTA0MjQyMTM2MzNaMFUxCzAJBgNVBAYTAlVTMRMwEQYDVQQKDApBcHBs
ZSBJbmMuMTEwLwYDVQQDDChBcHBsZSBJc3N1aW5nIEF1dGhvcml0eSBFQ0MgUm9v
dCBDQSAtIEcxMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAE7BhFhUOAzjz0TB/8hOTL
eC3PmqdOjQ/k/ZYNx2l4+N6u9x1N7qXpLqgy2IygddjsyDydeuRW+oxoderlKKuz
TJGEfw5B/MxGbRsq7ybzVpWaSLfdKFn/Wyg+0XA1wzN3o4GFMIGCMA8GA1UdEwEB
/wQFMAMBAf8wQAYDVR0SBDkwN4Y1aHR0cHM6Ly93d3cuYXBwbGUuY29tL2NlcnRp
ZmljYXRlYXV0aG9yaXR5L2Fwa2kyMDI1MDUwHQYDVR0OBBYEFGUPcEXidXLDYWd7
H6Fl8uTsb9GnMA4GA1UdDwEB/wQEAwIBBjAKBggqhkjOPQQDAwNoADBlAjEA93FE
McoJf8hVP080WdFFb1bAROvmiOW/GGfvg7IMGC2T0uS1guywZJ1kIoc5hHjoAjBT
KjBXbunuxyMjUo07mXnfGDkCkW+ggIswW+mxcrKZvEy1EOciol+/N0ViI9jnBRw=
-----END CERTIFICATE-----`;

const APPLE_ROOT_AKI = 'ZQ9wReJ1csNhZ3sfoWXy5Oxv0ac';

function certificateDer(pem) {
    const base64 = pem
        .replace(/-----BEGIN CERTIFICATE-----/, '')
        .replace(/-----END CERTIFICATE-----/, '')
        .replace(/\s+/g, '');
    return Buffer.from(base64, 'base64');
}

function arrayBuffer(buffer) {
    return buffer.buffer.slice(buffer.byteOffset, buffer.byteOffset + buffer.byteLength);
}

function captureWarnings(t) {
    const originalWarn = console.warn;
    const warnings = [];
    console.warn = message => warnings.push(message);
    t.after(() => {
        console.warn = originalWarn;
    });
    return warnings;
}

function assertMissingCrlCertificateImported(issuers, trustList, entityType = 'government') {
    const issuer = issuers[APPLE_ROOT_AKI];

    assert.equal(issuer.issuer_id, `x509_aki:${APPLE_ROOT_AKI}`);
    assert.equal(issuer.entity_type, entityType);
    assert.deepEqual(issuer.trust_scopes, ['government_issued_id']);
    assert.equal(issuer.display.name, 'Apple Inc.');
    assert.equal(issuer.certificates.length, 1);
    assert.deepEqual(issuer.certificates[0].trust_lists, [trustList]);
}

test('fetchFromUV imports certificates that do not advertise a CRL', async t => {
    const originalFetch = globalThis.fetch;
    const warnings = captureWarnings(t);

    try {
        globalThis.fetch = async () => ({
            ok: true,
            json: async () => [
                {
                    issuer_id: `x509_aki:${APPLE_ROOT_AKI}`,
                    entity_type: 'commercial',
                    certificates: [
                        {
                            data: APPLE_ROOT_CERT_WITHOUT_CRL,
                            format: 'pem'
                        }
                    ]
                }
            ]
        });

        const issuers = await fetchFromUV();

        assertMissingCrlCertificateImported(issuers, 'uv', 'commercial');
        assert.ok(warnings.includes('1 certificate(s) have missing CRLs'));
    } finally {
        globalThis.fetch = originalFetch;
    }
});

test('fetchFromAAMVA imports certificates that do not advertise a CRL', async t => {
    const originalFetch = globalThis.fetch;
    const warnings = captureWarnings(t);
    const payload = cbor2.encode({
        certificateInfos: [
            {
                certificate: certificateDer(APPLE_ROOT_CERT_WITHOUT_CRL)
            }
        ]
    });
    const vical = cbor2.encode([new Uint8Array(), {}, payload, new Uint8Array()]);

    try {
        globalThis.fetch = async () => ({
            ok: true,
            arrayBuffer: async () => arrayBuffer(vical)
        });

        const issuers = await fetchFromAAMVA();

        assertMissingCrlCertificateImported(issuers, 'aamva_dts');
        assert.ok(warnings.includes('1 certificate(s) have missing CRLs'));
    } finally {
        globalThis.fetch = originalFetch;
    }
});
