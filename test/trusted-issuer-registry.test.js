import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import TrustedIssuerRegistry from '../scripts/trusted-issuer-registry.js';
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

        const registry = new TrustedIssuerRegistry({ cacheEnabled: false });
        const issuer = await registry.getIssuerFromX509AKI(aki);
        assert.equal(issuer.issuer_id, `x509_aki:${aki}`);
    } finally {
        globalThis.fetch = originalFetch;
    }
});

test('minorVersion', () => {
    assert.equal(TrustedIssuerRegistry.minorVersion, MINOR_VERSION);
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

        const registry = new TrustedIssuerRegistry();
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

        const registry = new TrustedIssuerRegistry();
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

        const registry = new TrustedIssuerRegistry();
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

        const registry = new TrustedIssuerRegistry();
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

        const registry = new TrustedIssuerRegistry();
        await assert.rejects(() => registry.getIssuerFromX509AKI('retry-me'), /Failed to fetch issuer retry-me: 503/);
        assert.equal(await registry.getIssuerFromX509AKI('retry-me'), null);
        assert.equal(calls, 2);
    } finally {
        globalThis.fetch = originalFetch;
    }
});
