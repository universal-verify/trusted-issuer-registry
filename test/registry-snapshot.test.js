import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync } from 'node:fs';

const AKI = 'rX7vmMbQz-Qkb83hZ7xXO4PRJKA';
const readIssuer = name => JSON.parse(readFileSync(new URL(`../issuers/x509_aki/${name}`, import.meta.url), 'utf8'));
const ISSUER = readIssuer(`${AKI}.json`);
const PEM = ISSUER.certificates[0].data;
const SNAPSHOT = JSON.parse(readFileSync(new URL('../build/registry.json', import.meta.url), 'utf8'));
const VARIANTS = [
    '../scripts/trusted-issuer-registry.js',
    '../build/trusted-issuer-registry.js',
    '../build/trusted-issuer-registry.min.js',
    '../build/trusted-issuer-registry.bundled.js',
    '../build/trusted-issuer-registry.bundled.min.js',
];

for(const variant of VARIANTS) {
    test(`${variant}: snapshot lookups preserve registry trust without network requests`, async t => {
        const sdk = await import(variant);
        const fetch = t.mock.method(globalThis, 'fetch', async () => assert.fail('Snapshot must not fetch registry data'));
        const snapshot = { version: 'informational', issuers: [structuredClone(ISSUER)] };
        const registry = new sdk.Registry({ registrySnapshot: snapshot, cacheEnabled: false, cacheTTL: 0 });
        snapshot.issuers[0].display.name = 'Changed after construction';
        assert.equal(await registry.getEndOfLifeDate(), null);
        assert.deepEqual(await registry.getIssuerFromX509AKI(AKI), ISSUER);
        const result = await registry.resolveCertificateTrust(PEM, {
            trustLists: [sdk.TrustList.UV], trustScope: sdk.TrustScope.GOVERNMENT_ISSUED_ID,
        });
        assert.equal(result.trusted, true);
        assert.deepEqual(result.issuer.certificates[0].trust_lists, ['uv']);
        assert.equal(result.issuer.certificates[0].revocationStatus, 'not_checked');
        assert.equal('signature' in result.issuer, false);
        assert.equal((await registry.resolveCertificateTrust(PEM)).trusted, false);
        assert.equal(await registry.getIssuerFromX509AKI('missing'), null);
        const filtered = await registry.resolveCertificateTrust(PEM, { trustLists: [sdk.TrustList.AAMVA_DTS] });
        assert.deepEqual(filtered.untrustedReasons, [sdk.UntrustedReason.ISSUER_CERTIFICATE_NOT_IN_TRUST_LISTS]);
        const wrongScope = await registry.resolveCertificateTrust(PEM, { trustLists: [sdk.TrustList.UV], trustScope: sdk.TrustScope.DOCUMENT_SIGNING });
        assert.deepEqual(wrongScope.untrustedReasons, [sdk.UntrustedReason.ISSUER_MISSING_REQUIRED_TRUST_SCOPE]);
        result.issuer.display.name = 'Changed result';
        result.issuer.certificates[0].trust_lists.push('changed');
        const lookup = await registry.getIssuerFromX509AKI(AKI);
        lookup.display.name = 'Changed lookup';
        assert.deepEqual(await registry.getIssuerFromX509AKI(AKI), ISSUER);
        assert.equal(fetch.mock.callCount(), 0);
    });

    test(`${variant}: empty snapshots and user-provided certificates stay offline`, async t => {
        const sdk = await import(variant);
        t.mock.method(globalThis, 'fetch', async () => assert.fail('Empty snapshots must not enable live lookups'));
        const empty = new sdk.Registry({ registrySnapshot: { issuers: [] } });
        assert.equal(await empty.getEndOfLifeDate(), null);
        assert.equal(await empty.getIssuerFromX509AKI(AKI), null);
        assert.deepEqual(await empty.resolveCertificateTrust(PEM, { trustLists: [sdk.TrustList.UV] }), {
            trusted: false, untrustedReasons: [sdk.UntrustedReason.ISSUER_CERTIFICATE_NOT_FOUND],
        });
        const registry = new sdk.Registry({
            registrySnapshot: { issuers: [] }, trustedIssuerCertificates: [PEM],
        });
        assert.equal((await registry.resolveCertificateTrust(PEM)).trusted, true);
        assert.deepEqual((await registry.getIssuerFromX509AKI(AKI)).certificates[0].trust_lists, ['user_provided']);
        const merged = new sdk.Registry({
            registrySnapshot: { issuers: [ISSUER] },
            trustedIssuerCertificates: [{ data: PEM, display: { name: 'My issuer' }, trust_scopes: [sdk.TrustScope.DOCUMENT_SIGNING] }],
        });
        const issuer = await merged.getIssuerFromX509AKI(AKI);
        assert.equal(issuer.display.name, 'My issuer');
        assert.deepEqual(issuer.certificates[0].trust_lists, ['user_provided', 'uv']);
        assert.deepEqual(issuer.trust_scopes, ['document_signing', 'government_issued_id']);
        assert.equal('signature' in issuer, false);
    });

    test(`${variant}: malformed and tampered snapshots never fall back to the CDN`, async t => {
        const sdk = await import(variant);
        t.mock.method(console, 'error', () => {});
        t.mock.method(globalThis, 'fetch', async () => assert.fail('Invalid snapshots must not fall back to the registry'));
        for(const registrySnapshot of [
            null, [], {}, { issuers: null }, { version: 3, issuers: [] }, { issuers: [null] },
            { issuers: [{ ...ISSUER, issuer_id: 'unsupported:issuer' }] },
            { issuers: [{ ...ISSUER, certificates: undefined }] },
            { issuers: [{ ...ISSUER, signature: undefined }] },
            { issuers: [{ ...ISSUER, signature: '' }] },
            { issuers: [ISSUER, ISSUER] },
        ]) {
            assert.throws(() => new sdk.Registry({ registrySnapshot }), /snapshot/i);
        }
        const tampered = structuredClone(ISSUER);
        tampered.display.name = 'Forged issuer';
        const registry = new sdk.Registry({ registrySnapshot: { issuers: [tampered] } });
        await assert.rejects(registry.getIssuerFromX509AKI(AKI), /Invalid registry snapshot signature/);
        const result = await registry.resolveCertificateTrust(PEM, { trustLists: [sdk.TrustList.UV] });
        assert.equal(result.trusted, false);
        assert.deepEqual(result.untrustedReasons, [sdk.UntrustedReason.ISSUER_CERTIFICATE_NOT_FOUND, sdk.UntrustedReason.ISSUER_FETCH_FAILED]);
    });

    test(`${variant}: snapshot mode still performs configured CRL requests`, async t => {
        const sdk = await import(variant);
        const fetch = t.mock.method(globalThis, 'fetch', async url => {
            assert.ok(!url.includes('cdn.jsdelivr.net'));
            return new Response(null, { status: 404 });
        });
        const registry = new sdk.Registry({ registrySnapshot: SNAPSHOT, revocationCheckMode: sdk.RevocationCheckMode.REQUIRED });
        const result = await registry.resolveCertificateTrust(PEM, { trustLists: [sdk.TrustList.UV] });
        assert.equal(result.trusted, false);
        assert.deepEqual(result.untrustedReasons, [sdk.UntrustedReason.REVOCATION_STATUS_UNDETERMINED]);
        assert.equal(result.issuer.certificates[0].revocationStatus, 'not_checked');
        assert.ok(fetch.mock.callCount() > 0);
        assert.equal(await registry.getEndOfLifeDate(), null);
    });
}

test('snapshot signatures are verified once across concurrent lookups, independently of HTTP caching', async t => {
    const { Registry } = await import(VARIANTS[0]);
    t.mock.method(globalThis, 'fetch', async () => assert.fail('Snapshot must not fetch'));
    const verify = t.mock.method(crypto.subtle, 'verify');
    const registry = new Registry({ registrySnapshot: { issuers: [ISSUER] }, cacheEnabled: false });
    await Promise.all(Array.from({ length: 10 }, () => registry.getIssuerFromX509AKI(AKI)));
    await registry.getIssuerFromX509AKI(AKI);
    assert.equal(verify.mock.callCount(), 1);
});

test('snapshot lookups retain signed certificate-less issuer records', async t => {
    const { Registry } = await import(VARIANTS[0]);
    t.mock.method(globalThis, 'fetch', async () => assert.fail('Tombstones must not fetch'));
    const tombstone = readdirSync(new URL('../issuers/x509_aki/', import.meta.url))
        .filter(name => name.endsWith('.json')).map(readIssuer).find(issuer => issuer.certificates.length === 0);
    assert.ok(tombstone);
    const registry = new Registry({ registrySnapshot: { issuers: [tombstone] } });
    assert.deepEqual(await registry.getIssuerFromX509AKI(tombstone.issuer_id.slice('x509_aki:'.length)), tombstone);
});

test('omitted and undefined snapshots retain live registry lookup behavior', async t => {
    const { Registry } = await import(VARIANTS[0]);
    const fetch = t.mock.method(globalThis, 'fetch', async () => new Response(JSON.stringify(ISSUER)));
    for(const options of [{}, { registrySnapshot: undefined }]) {
        assert.deepEqual(await new Registry(options).getIssuerFromX509AKI(AKI), ISSUER);
    }
    assert.equal(fetch.mock.callCount(), 2);
});
