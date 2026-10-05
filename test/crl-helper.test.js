import test from 'node:test';
import assert from 'node:assert/strict';
import { checkCertificateRevocation } from '../scripts/crl-helper.js';
import { parsePemCertificate } from '../scripts/certificate-helper.js';

const CRL_URL = 'https://example.test/test.crl';
const TEST_IACA_CERT = `-----BEGIN CERTIFICATE-----
MIIBkDCCATagAwIBAgIUbHUBhA6c7mDVnFLnyOOk1xYW4y0wCgYIKoZIzj0EAwIw
FDESMBAGA1UEAwwJVGVzdCBJQUNBMB4XDTI2MDkyNjE4MTExMloXDTM2MDkyMzE4
MTExMlowFDESMBAGA1UEAwwJVGVzdCBJQUNBMFkwEwYHKoZIzj0CAQYIKoZIzj0D
AQcDQgAEKuHmTNyXR4teRBzniaPBMt7b8RfnvIqwq3Ed7ycmpU7B4lusX4fGZROy
vSYH9q8/ITQhiaFkrODt9jNb2aoph6NmMGQwEgYDVR0TAQH/BAgwBgEB/wIBATAO
BgNVHQ8BAf8EBAMCAQYwHQYDVR0OBBYEFKE40Bi/qWwHQYcDQVp64R8lZJLiMB8G
A1UdIwQYMBaAFKE40Bi/qWwHQYcDQVp64R8lZJLiMAoGCCqGSM49BAMCA0gAMEUC
IB/Sf/Rrfe/NtvP40wiqvxgh4tmsaFhb4NafBER6zj1CAiEAyiGwvQoWBMzFPDW6
9Mf/Q3Yuy5xMPy2WiUkJeN2BjTY=
-----END CERTIFICATE-----`;
const TEST_DOCUMENT_SIGNER_CERT = `-----BEGIN CERTIFICATE-----
MIIBtTCCAVugAwIBAgICEAEwCgYIKoZIzj0EAwIwFDESMBAGA1UEAwwJVGVzdCBJ
QUNBMB4XDTI2MDkyNDE3MDQ0OFoXDTM2MDkyMTE3MDQ0OFowHzEdMBsGA1UEAwwU
VGVzdCBEb2N1bWVudCBTaWduZXIwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAATF
PicZCdTSGicPpPr5zF/SNR3BDp1E6zztbeE0n+Gw5QqlTq+yNXxC/Mph7h2sc2VW
VeFpA837cQie/hOFUmpco4GRMIGOMAwGA1UdEwEB/wQCMAAwDgYDVR0PAQH/BAQD
AgeAMB0GA1UdDgQWBBTLxDfKjx3XTsN01efByUymRC7d3jAfBgNVHSMEGDAWgBSh
ONAYv6lsB0GHA0FaeuEfJWSS4jAuBgNVHR8EJzAlMCOgIaAfhh1odHRwczovL2V4
YW1wbGUudGVzdC90ZXN0LmNybDAKBggqhkjOPQQDAgNIADBFAiEAhjxW7T429LPy
riSTqnSboT2Y0Olasia1B9Cge8knIEICIG0A5O9wuioXSniU/5ryATtJjHvQN0j/
JikmryiDWnYJ
-----END CERTIFICATE-----`;
const CURRENT_EMPTY_CRL = `-----BEGIN X509 CRL-----
MIGsMFQCAQEwCgYIKoZIzj0EAwIwFDESMBAGA1UEAwwJVGVzdCBJQUNBFw0yNjA5
MjQxNzA0NDhaFw0zNjAxMDEwMDAwMDBaoA8wDTALBgNVHRQEBAICEAAwCgYIKoZI
zj0EAwIDSAAwRQIgB7OdFVmVr5iCtq84sHlnODgW5N8rOlWlhWeSfJCuv+ICIQC+
ozd2wJmqIomydzGRuXvf6lg49yfOCZIK3oajkK4bQw==
-----END X509 CRL-----`;
const STALE_EMPTY_CRL = `-----BEGIN X509 CRL-----
MIGsMFQCAQEwCgYIKoZIzj0EAwIwFDESMBAGA1UEAwwJVGVzdCBJQUNBFw0xOTAx
MDEwMDAwMDBaFw0yMDAxMDEwMDAwMDBaoA8wDTALBgNVHRQEBAICEAEwCgYIKoZI
zj0EAwIDSAAwRQIgIPbhgplWa4OuF3v/UjbKlJd3X+RxKzFz+Puea8fypasCIQCB
O13gcBzpEjbiYrc3V1XQcUUn1eo88MCLGeSpPXy2tA==
-----END X509 CRL-----`;

const issuerCertificate = { data: TEST_IACA_CERT };
const documentSignerCertificate = parsePemCertificate(TEST_DOCUMENT_SIGNER_CERT);

test('checkCertificateRevocation caches stale CRLs using normal cache TTL', async () => {
    const cache = new Map();
    let fetchCount = 0;

    await withMockedFetch(async (url) => {
        fetchCount++;
        assert.equal(url, CRL_URL);
        return crlResponse(textBytes(fetchCount === 1 ? STALE_EMPTY_CRL : CURRENT_EMPTY_CRL));
    }, async () => {
        const first = await checkCertificateRevocation(documentSignerCertificate, issuerCertificate, { cache: cache });
        const second = await checkCertificateRevocation(documentSignerCertificate, issuerCertificate, { cache: cache });

        assert.equal(fetchCount, 1);
        assert.deepEqual(Object.keys(first).sort(), ['checked', 'error', 'revoked']);
        assert.equal(first.checked, false);
        assert.equal(first.revoked, false);
        assert.match(first.error, /CRL is stale/);
        assert.deepEqual(Object.keys(second).sort(), ['checked', 'error', 'revoked']);
        assert.equal(second.checked, false);
        assert.equal(second.revoked, false);
        assert.match(second.error, /CRL is stale/);
        assert.ok(cache.get(CRL_URL).expiresAt > Date.now());
    });
});

test('checkCertificateRevocation caps CRL cache expiration at future nextUpdate when it is sooner than TTL', async () => {
    const cache = new Map();
    const longTTL = 1000 * 60 * 60 * 24 * 365 * 20;

    await withMockedFetch(async (url) => {
        assert.equal(url, CRL_URL);
        return crlResponse(textBytes(CURRENT_EMPTY_CRL));
    }, async () => {
        const result = await checkCertificateRevocation(documentSignerCertificate, issuerCertificate, {
            cache: cache,
            cacheTTL: longTTL,
        });

        assert.deepEqual(Object.keys(result).sort(), ['checked', 'revoked']);
        assert.equal(result.checked, true);
        assert.equal(result.revoked, false);
        assert.equal(cache.get(CRL_URL).expiresAt, Date.parse('2036-01-01T00:00:00Z'));
    });
});

test('checkCertificateRevocation normalizes CRL fetch timeouts', async () => {
    await withMockedFetch(async (_url, options = {}) => {
        return new Promise((_resolve, reject) => {
            options.signal.addEventListener('abort', () => {
                const error = new Error('The operation was aborted');
                error.name = 'AbortError';
                reject(error);
            });
        });
    }, async () => {
        const result = await checkCertificateRevocation(documentSignerCertificate, issuerCertificate, {
            timeout: 1,
        });

        assert.deepEqual(Object.keys(result).sort(), ['checked', 'error', 'revoked']);
        assert.equal(result.checked, false);
        assert.equal(result.revoked, false);
        assert.match(result.error, /CRL request timed out after 1ms/);
    });
});

async function withMockedFetch(fetchImplementation, callback) {
    const originalFetch = globalThis.fetch;
    globalThis.fetch = fetchImplementation;
    try {
        return await callback();
    } finally {
        globalThis.fetch = originalFetch;
    }
}

function crlResponse(crlBytes) {
    return {
        ok: true,
        arrayBuffer: async () => crlBytes.buffer.slice(crlBytes.byteOffset, crlBytes.byteOffset + crlBytes.byteLength),
    };
}

function textBytes(text) {
    return new TextEncoder().encode(text);
}
