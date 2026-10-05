import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { Registry, RevocationCheckMode, TrustScope, UntrustedReason } from '../scripts/trusted-issuer-registry.js';
import { MINOR_VERSION, REGISTRY_URL_BASE } from '../scripts/constants.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

function readIssuerFixture(aki) {
    const issuerPath = path.resolve(__dirname, '..', 'issuers', 'x509_aki', `${aki}.json`);
    return JSON.parse(fs.readFileSync(issuerPath, 'utf8'));
}

test('getIssuerFromX509AKI', async () => {
    const originalFetch = globalThis.fetch;
    const aki = 'taXH_AFcuSnQgLECaiofOquMVcQ';
    const issuerFixture = readIssuerFixture(aki);
    const issuerUrl = `${REGISTRY_URL_BASE}/issuers/x509_aki/${aki}.json`;

    try {
        globalThis.fetch = async url => {
            assert.equal(url, issuerUrl);
            return {
                ok: true,
                json: async () => JSON.parse(JSON.stringify(issuerFixture))
            };
        };

        const registry = new Registry({ cacheEnabled: false });
        const issuer = await registry.getIssuerFromX509AKI(aki);
        assert.equal(issuer.issuer_id, `x509_aki:${aki}`);
    } finally {
        globalThis.fetch = originalFetch;
    }
});

test('minorVersion', () => {
    assert.equal(Registry.minorVersion, MINOR_VERSION);
    assert.equal(RevocationCheckMode.SKIP, 'skip');
    assert.equal(RevocationCheckMode.BEST_EFFORT, 'best_effort');
    assert.equal(UntrustedReason.REVOCATION_STATUS_UNDETERMINED, 'Unable to determine certificate revocation status');
});

test('constructor defaults CRL config and user trusted issuers', () => {
    const registry = new Registry();

    assert.deepEqual(registry._crl, {
        mode: RevocationCheckMode.SKIP,
        timeout: 5000
    });
    assert.ok(registry._cache instanceof Map);
    assert.ok(registry._crlCache instanceof Map);
    assert.equal(Object.getPrototypeOf(registry._userTrustedIssuers), null);
    assert.deepEqual(Object.keys(registry._userTrustedIssuers), []);
});

test('constructor normalizes PEM trusted issuer certificates', () => {
    const issuerFixture = readIssuerFixture('ZQ9wReJ1csNhZ3sfoWXy5Oxv0ac');
    const registry = new Registry({
        trustedIssuerCertificates: [issuerFixture.certificates[0].data]
    });
    const issuer = registry._userTrustedIssuers.ZQ9wReJ1csNhZ3sfoWXy5Oxv0ac;

    assert.deepEqual(Object.keys(registry._userTrustedIssuers), ['ZQ9wReJ1csNhZ3sfoWXy5Oxv0ac']);
    assert.equal(issuer.issuer_id, 'x509_aki:ZQ9wReJ1csNhZ3sfoWXy5Oxv0ac');
    assert.equal(issuer.entity_type, 'other');
    assert.deepEqual(issuer.entity_metadata, { country: 'US' });
    assert.deepEqual(issuer.display, { name: 'Apple Inc.' });
    assert.deepEqual(issuer.trust_scopes, []);
    assert.deepEqual(issuer.certificates[0].trust_lists, ['user_provided']);
    assert.equal(issuer.certificates[0].format, 'pem');
    assert.match(issuer.certificates[0].data, /^-----BEGIN CERTIFICATE-----\n/);
});

test('constructor normalizes object trusted issuer certificates with overrides', () => {
    const issuerFixture = readIssuerFixture('ZQ9wReJ1csNhZ3sfoWXy5Oxv0ac');
    const registry = new Registry({
        crl: {
            mode: RevocationCheckMode.REQUIRED,
            timeout: 2500
        },
        trustedIssuerCertificates: [
            {
                data: issuerFixture.certificates[0].data,
                format: 'pem',
                trust_scopes: [TrustScope.DOCUMENT_SIGNING],
                entity_type: 'educational_institution',
                entity_metadata: {
                    country: 'CA'
                },
                display: {
                    name: 'Example University'
                }
            }
        ]
    });
    const issuer = registry._userTrustedIssuers.ZQ9wReJ1csNhZ3sfoWXy5Oxv0ac;

    assert.deepEqual(registry._crl, {
        mode: RevocationCheckMode.REQUIRED,
        timeout: 2500
    });
    assert.deepEqual(Object.keys(registry._userTrustedIssuers), ['ZQ9wReJ1csNhZ3sfoWXy5Oxv0ac']);
    assert.equal(issuer.entity_type, 'educational_institution');
    assert.deepEqual(issuer.entity_metadata, { country: 'CA' });
    assert.deepEqual(issuer.display, { name: 'Example University' });
    assert.deepEqual(issuer.trust_scopes, [TrustScope.DOCUMENT_SIGNING]);
});

test('constructor rejects unsupported CRL check modes', () => {
    assert.throws(() => new Registry({
        crl: {
            mode: 'strict'
        }
    }), /Unsupported CRL check mode: strict/);
});

test('getIssuerFromX509AKI returns user trusted issuers before fetching remote registry', async () => {
    const originalFetch = globalThis.fetch;
    const issuerFixture = readIssuerFixture('ZQ9wReJ1csNhZ3sfoWXy5Oxv0ac');
    let fetchCalled = false;

    try {
        globalThis.fetch = async () => {
            fetchCalled = true;
            throw new Error('Unexpected fetch');
        };

        const registry = new Registry({
            trustedIssuerCertificates: [issuerFixture.certificates[0].data]
        });
        const issuer = await registry.getIssuerFromX509AKI('ZQ9wReJ1csNhZ3sfoWXy5Oxv0ac');

        assert.equal(fetchCalled, false);
        assert.equal(issuer.issuer_id, 'x509_aki:ZQ9wReJ1csNhZ3sfoWXy5Oxv0ac');
    } finally {
        globalThis.fetch = originalFetch;
    }
});

test('resolveCertificateTrust is reserved for the trust resolver API', async () => {
    const registry = new Registry();

    await assert.rejects(() => registry.resolveCertificateTrust(null), /resolveCertificateTrust is not implemented yet/);
});

test('getEndOfLifeDate caches successful responses', async () => {
    const originalFetch = globalThis.fetch;
    let calls = 0;
    const endOfLife = 1761782400;

    try {
        globalThis.fetch = async () => {
            calls += 1;
            return {
                ok: true,
                json: async () => ({
                    version: MINOR_VERSION,
                    end_of_life: endOfLife
                })
            };
        };

        const registry = new Registry();
        const first = await registry.getEndOfLifeDate();
        first.setTime(0);
        const second = await registry.getEndOfLifeDate();

        assert.equal(calls, 1);
        assert.equal(second.getTime(), endOfLife * 1000);
    } finally {
        globalThis.fetch = originalFetch;
    }
});

test('getEndOfLifeDate caches missing deprecation notices', async () => {
    const originalFetch = globalThis.fetch;
    let calls = 0;

    try {
        globalThis.fetch = async () => {
            calls += 1;
            return {
                ok: false,
                status: 404
            };
        };

        const registry = new Registry();
        assert.equal(await registry.getEndOfLifeDate(), null);
        assert.equal(await registry.getEndOfLifeDate(), null);
        assert.equal(calls, 1);
    } finally {
        globalThis.fetch = originalFetch;
    }
});

test('getEndOfLifeDate does not cache transient HTTP failures', async () => {
    const originalFetch = globalThis.fetch;
    let calls = 0;
    const endOfLife = 1761782400;

    try {
        globalThis.fetch = async () => {
            calls += 1;
            if (calls === 1) {
                return {
                    ok: false,
                    status: 500
                };
            }
            return {
                ok: true,
                json: async () => ({
                    version: MINOR_VERSION,
                    end_of_life: endOfLife
                })
            };
        };

        const registry = new Registry();
        await assert.rejects(() => registry.getEndOfLifeDate(), /Failed to fetch deprecation notice: 500/);
        assert.equal((await registry.getEndOfLifeDate()).getTime(), endOfLife * 1000);
        assert.equal(calls, 2);
    } finally {
        globalThis.fetch = originalFetch;
    }
});

test('getIssuerFromX509AKI caches missing issuers', async () => {
    const originalFetch = globalThis.fetch;
    let calls = 0;

    try {
        globalThis.fetch = async () => {
            calls += 1;
            return {
                ok: false,
                status: 404
            };
        };

        const registry = new Registry();
        assert.equal(await registry.getIssuerFromX509AKI('missing'), null);
        assert.equal(await registry.getIssuerFromX509AKI('missing'), null);
        assert.equal(calls, 1);
    } finally {
        globalThis.fetch = originalFetch;
    }
});

test('getIssuerFromX509AKI throws and retries on non-404 HTTP failures', async () => {
    const originalFetch = globalThis.fetch;
    let calls = 0;

    try {
        globalThis.fetch = async () => {
            calls += 1;
            if (calls === 1) {
                return {
                    ok: false,
                    status: 503
                };
            }
            return {
                ok: false,
                status: 404
            };
        };

        const registry = new Registry();
        await assert.rejects(() => registry.getIssuerFromX509AKI('retry-me'), /Failed to fetch issuer retry-me: 503/);
        assert.equal(await registry.getIssuerFromX509AKI('retry-me'), null);
        assert.equal(calls, 2);
    } finally {
        globalThis.fetch = originalFetch;
    }
});
