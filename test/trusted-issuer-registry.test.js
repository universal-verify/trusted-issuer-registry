import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { Registry, RevocationCheckMode, TrustScope, UntrustedReason } from '../scripts/trusted-issuer-registry.js';
import { MINOR_VERSION, REGISTRY_URL_BASE } from '../scripts/constants.js';
import { CachedFetcher } from '../scripts/cached-fetcher.js';

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
            return new Response(JSON.stringify(issuerFixture));
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
    assert.equal(UntrustedReason.REVOCATION_STATUS_UNDETERMINED, 'revocation_status_undetermined');
});

test('untrusted reason values are lowercase versions of their enum keys', () => {
    for(const [key, value] of Object.entries(UntrustedReason)) {
        assert.equal(value, key.toLowerCase());
    }
});

test('constructor defaults revocation mode, request timeout, and user trusted issuers', () => {
    const registry = new Registry();

    assert.equal(registry._revocationCheckMode, RevocationCheckMode.SKIP);
    assert.ok(registry._cachedFetcher instanceof CachedFetcher);
    assert.equal(registry._cachedFetcher._timeout, 10000);
    assert.equal(registry._cachedFetcher.cacheEnabled, true);
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
        cacheEnabled: false,
        cacheTTL: 60000,
        revocationCheckMode: RevocationCheckMode.REQUIRED,
        timeout: 2500,
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

    assert.equal(registry._revocationCheckMode, RevocationCheckMode.REQUIRED);
    assert.equal(registry._cachedFetcher._timeout, 2500);
    assert.equal(registry._cachedFetcher.cacheEnabled, false);
    assert.deepEqual(Object.keys(registry._userTrustedIssuers), ['ZQ9wReJ1csNhZ3sfoWXy5Oxv0ac']);
    assert.equal(issuer.entity_type, 'educational_institution');
    assert.deepEqual(issuer.entity_metadata, { country: 'CA' });
    assert.deepEqual(issuer.display, { name: 'Example University' });
    assert.deepEqual(issuer.trust_scopes, [TrustScope.DOCUMENT_SIGNING]);
});

test('constructor rejects unsupported CRL check modes', () => {
    assert.throws(() => new Registry({
        revocationCheckMode: 'strict'
    }), /Unsupported CRL check mode: strict/);
});

test('getIssuerFromX509AKI checks the registry and returns a copy of the user issuer on 404', async t => {
    const aki = 'ZQ9wReJ1csNhZ3sfoWXy5Oxv0ac';
    const issuerFixture = readIssuerFixture(aki);
    let calls = 0;
    t.mock.method(globalThis, 'fetch', async url => {
        calls++;
        assert.equal(url, `${REGISTRY_URL_BASE}/issuers/x509_aki/${aki}.json`);
        return new Response(null, { status: 404 });
    });
    const registry = new Registry({
        trustedIssuerCertificates: [issuerFixture.certificates[0].data],
    });
    const expected = structuredClone(registry._userTrustedIssuers[aki]);
    const issuer = await registry.getIssuerFromX509AKI(aki);
    assert.deepEqual(issuer, expected);
    issuer.display.name = 'Modified';
    issuer.certificates[0].trust_lists.push('modified');
    assert.deepEqual(await registry.getIssuerFromX509AKI(aki), expected);
    assert.equal(calls, 1);
});

test('getIssuerFromX509AKI propagates registry failures even when a user issuer exists', async t => {
    const aki = 'ZQ9wReJ1csNhZ3sfoWXy5Oxv0ac';
    const issuerFixture = readIssuerFixture(aki);
    let calls = 0;
    t.mock.method(globalThis, 'fetch', async () => {
        calls++;
        if(calls === 1) throw new Error('Network unavailable');
        return new Response(null, { status: calls === 2 ? 503 : 404 });
    });
    const registry = new Registry({
        trustedIssuerCertificates: [issuerFixture.certificates[0].data],
    });
    await assert.rejects(registry.getIssuerFromX509AKI(aki), /Network unavailable/);
    await assert.rejects(registry.getIssuerFromX509AKI(aki), /Failed to fetch issuer .*: 503/);
    assert.equal((await registry.getIssuerFromX509AKI(aki)).issuer_id, `x509_aki:${aki}`);
    assert.equal(calls, 3);
});

test('resolveCertificateTrust reports missing certificates', async () => {
    const registry = new Registry();

    assert.deepEqual(await registry.resolveCertificateTrust(null), {
        trusted: false,
        untrustedReasons: [UntrustedReason.CERTIFICATE_MISSING],
    });
});

test('getEndOfLifeDate caches successful responses', async () => {
    const originalFetch = globalThis.fetch;
    let calls = 0;
    const endOfLife = 1761782400;

    try {
        globalThis.fetch = async () => {
            calls += 1;
            return new Response(JSON.stringify({ version: MINOR_VERSION, end_of_life: endOfLife }));
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

test('malformed deprecation notices cache the parse error until TTL expires', async t => {
    let now = Date.now();
    let calls = 0;
    const endOfLife = 1761782400;
    t.mock.method(Date, 'now', () => now);
    t.mock.method(globalThis, 'fetch', async () => {
        calls++;
        return new Response(calls === 1 ? '{"version":' : JSON.stringify({ version: MINOR_VERSION, end_of_life: endOfLife }));
    });
    const registry = new Registry({ cacheTTL: 100 });
    await assert.rejects(registry.getEndOfLifeDate(), SyntaxError);
    await assert.rejects(registry.getEndOfLifeDate(), SyntaxError);
    assert.equal(calls, 1);
    now += 100;
    assert.equal((await registry.getEndOfLifeDate()).getTime(), endOfLife * 1000);
    assert.equal(calls, 2);
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
            return new Response(JSON.stringify({ version: MINOR_VERSION, end_of_life: endOfLife }));
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

test('issuer and deprecation callers share requests independently of completed caching', async t => {
    const calls = new Map();
    t.mock.method(globalThis, 'fetch', async url => {
        calls.set(url, (calls.get(url) || 0) + 1);
        return new Response(null, { status: 404 });
    });
    const registry = new Registry({ cacheEnabled: false });
    const issuerUrl = `${REGISTRY_URL_BASE}/issuers/x509_aki/missing.json`;
    const deprecationUrl = `${REGISTRY_URL_BASE}/deprecation_notice.json`;

    assert.deepEqual(await Promise.all([
        registry.getIssuerFromX509AKI('missing'),
        registry.getIssuerFromX509AKI('missing'),
        registry.getEndOfLifeDate(),
        registry.getEndOfLifeDate(),
    ]), [null, null, null, null]);
    assert.equal(calls.get(issuerUrl), 1);
    assert.equal(calls.get(deprecationUrl), 1);
    await registry.getIssuerFromX509AKI('missing');
    await registry.getEndOfLifeDate();
    assert.equal(calls.get(issuerUrl), 2);
    assert.equal(calls.get(deprecationUrl), 2);
});

test('issuer JSON with an invalid signature is not cached', async t => {
    const aki = 'taXH_AFcuSnQgLECaiofOquMVcQ';
    const fixture = readIssuerFixture(aki);
    fixture.display.name = 'Tampered issuer';
    let calls = 0;
    t.mock.method(globalThis, 'fetch', async () => {
        calls++;
        return new Response(JSON.stringify(fixture));
    });
    const registry = new Registry();
    assert.equal(await registry.getIssuerFromX509AKI(aki), null);
    assert.equal(await registry.getIssuerFromX509AKI(aki), null);
    assert.equal(calls, 2);
});

test('the general timeout applies to issuer and deprecation requests without caching failures', async t => {
    let unavailable = true;
    let calls = 0;
    t.mock.method(globalThis, 'fetch', async (_url, { signal }) => {
        calls++;
        if(!unavailable) return new Response(null, { status: 404 });
        return new Promise((_resolve, reject) => {
            signal.addEventListener('abort', () => reject(new DOMException('Aborted', 'AbortError')));
        });
    });
    const registry = new Registry({ timeout: 1 });
    await assert.rejects(registry.getIssuerFromX509AKI('timeout'), {
        name: 'TimeoutError', message: 'Request timed out after 1ms',
    });
    await assert.rejects(registry.getEndOfLifeDate(), {
        name: 'TimeoutError', message: 'Request timed out after 1ms',
    });
    unavailable = false;
    assert.equal(await registry.getIssuerFromX509AKI('timeout'), null);
    assert.equal(await registry.getEndOfLifeDate(), null);
    assert.equal(calls, 4);
    await registry.getIssuerFromX509AKI('timeout');
    await registry.getEndOfLifeDate();
    assert.equal(calls, 4);
});
