import { before, test } from 'node:test';
import assert from 'node:assert/strict';
import * as asn1js from 'asn1js';
import {
    AttributeTypeAndValue,
    AuthorityKeyIdentifier,
    BasicConstraints,
    Certificate,
    CertificateRevocationList,
    CRLDistributionPoints,
    DistributionPoint,
    Extension,
    Extensions,
    GeneralName,
    RelativeDistinguishedNames,
    RevokedCertificate,
    Time,
} from 'pkijs';
import {
    Registry,
    RevocationCheckMode,
    TrustList,
    TrustScope,
    UntrustedReason,
    certificateToPem,
    parsePemCertificate,
    verifyCertificateSignature,
} from '../scripts/trusted-issuer-registry.js';
import { REGISTRY_URL_BASE } from '../scripts/constants.js';
import {
    ensurePKIjsCryptoEngine,
    getAuthorityKeyIdentifier,
    getSubjectKeyIdentifier,
} from '../scripts/certificate-helper.js';

const CRL_URL = 'https://example.test/issuer.crl';
const SDK_VARIANTS = [
    'trusted-issuer-registry.js',
    'trusted-issuer-registry.min.js',
    'trusted-issuer-registry.bundled.js',
    'trusted-issuer-registry.bundled.min.js',
];
const VALID_FROM = new Date('2000-01-01T00:00:00Z');
const VALID_UNTIL = new Date('2100-01-01T00:00:00Z');
const EXPIRED = new Date('2001-01-01T00:00:00Z');
const FUTURE = new Date('2090-01-01T00:00:00Z');
let issuer;
let renewedIssuer;
let expiredIssuer;
let futureIssuer;
let mismatchedIssuer;
let leaf;
let aki;
let leafKeyPair;

before(async () => {
    ensurePKIjsCryptoEngine();
    leafKeyPair = await generateKeyPair();
    issuer = await createIssuer();
    aki = getSubjectKeyIdentifier(issuer.certificate);
    renewedIssuer = await createIssuer({ keyPair: issuer.keyPair, serial: 2 });
    expiredIssuer = await createIssuer({ keyPair: issuer.keyPair, serial: 3, notAfter: EXPIRED });
    futureIssuer = await createIssuer({ keyPair: issuer.keyPair, serial: 4, notBefore: FUTURE });
    mismatchedIssuer = await createIssuer({ serial: 5 });
    leaf = await createLeaf();
});

test('verifyCertificateSignature is a standalone export that checks signatures without evaluating trust', async () => {
    assert.equal(await verifyCertificateSignature(leaf, issuer.certificate), true);
    assert.equal(await verifyCertificateSignature(leaf, mismatchedIssuer.certificate), false);
    assert.equal(await verifyCertificateSignature(leaf, expiredIssuer.certificate), true);
    const otherIssuer = await createIssuer({ keyPair: issuer.keyPair, name: 'Other issuer' });
    assert.equal(await verifyCertificateSignature(leaf, otherIssuer.certificate), false);
    assert.equal('verifyCertificateSignature' in Registry.prototype, false);
});

test('signature verification reuses certificates from its own PKIjs copy without serialization', async t => {
    const serializeCertificate = t.mock.method(leaf, 'toSchema');
    const serializeIssuer = t.mock.method(issuer.certificate, 'toSchema');
    assert.equal(await verifyCertificateSignature(leaf, issuer.certificate), true);
    assert.equal(serializeCertificate.mock.callCount(), 0);
    assert.equal(serializeIssuer.mock.callCount(), 0);
});

test('default trust lists use only user-provided certificates and omit empty reasons', async t => {
    mockFetch(t, async () => { throw new Error('Registry must not be requested'); });
    const registry = new Registry({ trustedIssuerCertificates: [issuer.pem] });
    const result = await registry.resolveCertificateTrust(leaf);

    assert.equal(result.trusted, true);
    assert.equal(result.issuer.issuer_id, `x509_aki:${aki}`);
    assert.equal('untrustedReasons' in result, false);
    assert.equal('untrustedReasons' in result.issuer, false);
    assert.deepEqual(result.issuer.certificates, [{
        data: issuer.pem,
        format: 'pem',
        trust_lists: ['user_provided'],
        trusted: true,
        revocationStatus: 'not_checked',
    }]);
    assert.equal((await registry.resolveCertificateTrust(certificateToPem(leaf), { trustLists: [] })).trusted, true);
});

test('missing AKI returns only its reason and never requests an issuer', async t => {
    mockFetch(t, async () => { throw new Error('Unexpected issuer fetch'); });
    const certificate = await createLeaf({ includeAKI: false, notAfter: EXPIRED });
    const result = await new Registry().resolveCertificateTrust(certificate, { trustLists: [TrustList.UV] });

    assert.deepEqual(result, { trusted: false, untrustedReasons: [UntrustedReason.CERTIFICATE_AKI_MISSING] });
});

test('AKI without a key identifier or with malformed data is treated as missing', async () => {
    const certificate = parsePemCertificate(certificateToPem(leaf));
    certificate.extensions = [extension('2.5.29.35', new AuthorityKeyIdentifier({
        authorityCertSerialNumber: new asn1js.Integer({ value: 1 }),
    }))];
    assert.equal(getAuthorityKeyIdentifier(certificate), null);

    certificate.extensions = [new Extension({ extnID: '2.5.29.35', extnValue: new Uint8Array([0xff]).buffer })];
    assert.equal(getAuthorityKeyIdentifier(certificate), null);
});

test('input certificate validity is reported while issuer evaluation continues', async () => {
    const registry = new Registry({ trustedIssuerCertificates: [issuer.pem] });
    for(const [dates, reason] of [
        [{ notBefore: FUTURE }, UntrustedReason.CERTIFICATE_NOT_YET_VALID],
        [{ notAfter: EXPIRED }, UntrustedReason.CERTIFICATE_EXPIRED],
    ]) {
        const result = await registry.resolveCertificateTrust(await createLeaf(dates));
        assert.equal(result.trusted, false);
        assert.deepEqual(result.untrustedReasons, [reason]);
        assert.equal(result.issuer.certificates[0].trusted, true);
    }
});

test('missing issuers and certificate-less issuers report certificate not found', async t => {
    let calls = 0;
    mockFetch(t, async () => {
        calls++;
        return { ok: false, status: 404 };
    });
    const registry = new Registry();
    const options = { trustLists: [TrustList.UV] };
    assert.deepEqual(await registry.resolveCertificateTrust(leaf, options), {
        trusted: false,
        untrustedReasons: [UntrustedReason.ISSUER_CERTIFICATE_NOT_FOUND],
    });
    await registry.resolveCertificateTrust(leaf, options);
    assert.equal(calls, 1);

    cacheIssuer(registry, []);
    const result = await registry.resolveCertificateTrust(leaf, options);
    assert.equal(result.trusted, false);
    assert.deepEqual(result.untrustedReasons, [UntrustedReason.ISSUER_CERTIFICATE_NOT_FOUND]);
    assert.equal('untrustedReasons' in result.issuer, false);
    assert.deepEqual(result.issuer.certificates, []);
});

test('empty trust lists never use an issuer from the registry cache', async () => {
    const registry = new Registry();
    cacheIssuer(registry, [entry(issuer)]);
    assert.deepEqual(await registry.resolveCertificateTrust(leaf), {
        trusted: false,
        untrustedReasons: [UntrustedReason.ISSUER_CERTIFICATE_NOT_FOUND],
    });
});

test('issuer merge preserves user metadata, unions scopes and certificates, and keeps user order', async () => {
    const registry = new Registry({ trustedIssuerCertificates: [
        {
            data: issuer.pem,
            entity_type: 'educational_institution',
            entity_metadata: { country: 'CA' },
            display: { name: 'User name' },
            trust_scopes: [TrustScope.DOCUMENT_SIGNING],
        },
        { data: expiredIssuer.pem, trust_scopes: [TrustScope.GOVERNMENT_ISSUED_ID] },
        issuer.pem,
    ] });
    const cachedIssuer = cacheIssuer(registry, [entry(renewedIssuer), entry(issuer), entry(expiredIssuer)]);
    const userIssuerBefore = JSON.stringify(registry._userTrustedIssuers);
    const cachedIssuerBefore = JSON.stringify(cachedIssuer);
    const result = await registry.resolveCertificateTrust(leaf, {
        trustLists: [TrustList.UV],
        trustScope: TrustScope.GOVERNMENT_ISSUED_ID,
    });

    assert.equal(result.trusted, true);
    assert.equal(result.issuer.entity_type, 'educational_institution');
    assert.deepEqual(result.issuer.entity_metadata, { country: 'CA', region: 'VA' });
    assert.deepEqual(result.issuer.display, { name: 'User name', logo: 'https://example.test/logo.png' });
    assert.deepEqual(result.issuer.trust_scopes, [TrustScope.DOCUMENT_SIGNING, TrustScope.GOVERNMENT_ISSUED_ID]);
    assert.deepEqual(result.issuer.certificates.map(certificate => certificate.data), [issuer.pem, expiredIssuer.pem, renewedIssuer.pem]);
    assert.deepEqual(result.issuer.certificates[0].trust_lists, ['user_provided', TrustList.UV]);
    assert.deepEqual(result.issuer.certificates[1].untrustedReasons, [UntrustedReason.ISSUER_CERTIFICATE_EXPIRED]);
    assert.equal('signature' in result.issuer, false);
    assert.equal(JSON.stringify(registry._userTrustedIssuers), userIssuerBefore);
    assert.equal(JSON.stringify(cachedIssuer), cachedIssuerBefore);

    result.issuer.display.name = 'Modified';
    result.issuer.certificates[0].trust_lists.push('modified');
    assert.equal(JSON.stringify(registry._userTrustedIssuers), userIssuerBefore);
    assert.equal(JSON.stringify(cachedIssuer), cachedIssuerBefore);
});

test('direct issuer lookup merges both sources without adding certificate trust results', async t => {
    mockFetch(t, async () => { throw new Error('Verified registry issuer is already cached'); });
    const registry = new Registry({ trustedIssuerCertificates: [
        {
            data: issuer.pem,
            entity_type: 'educational_institution',
            entity_metadata: { country: 'CA' },
            display: { name: 'User name' },
            trust_scopes: [TrustScope.DOCUMENT_SIGNING],
        },
        expiredIssuer.pem,
    ] });
    const cachedIssuer = cacheIssuer(registry, [entry(renewedIssuer), entry(issuer), entry(expiredIssuer)]);
    const userIssuerBefore = JSON.stringify(registry._userTrustedIssuers);
    const cachedIssuerBefore = JSON.stringify(cachedIssuer);
    const result = await registry.getIssuerFromX509AKI(aki);

    assert.equal(result.entity_type, 'educational_institution');
    assert.deepEqual(result.entity_metadata, { country: 'CA', region: 'VA' });
    assert.deepEqual(result.display, { name: 'User name', logo: 'https://example.test/logo.png' });
    assert.deepEqual(result.trust_scopes, [TrustScope.DOCUMENT_SIGNING, TrustScope.GOVERNMENT_ISSUED_ID]);
    assert.deepEqual(result.certificates, [
        entry(issuer, ['user_provided', TrustList.UV]),
        entry(expiredIssuer, ['user_provided', TrustList.UV]),
        entry(renewedIssuer),
    ]);
    assert.equal('signature' in result, false);
    const expected = structuredClone(result);
    result.display.name = 'Modified';
    result.certificates[0].trust_lists.push('modified');
    assert.deepEqual(await registry.getIssuerFromX509AKI(aki), expected);
    assert.equal(JSON.stringify(registry._userTrustedIssuers), userIssuerBefore);
    assert.equal(JSON.stringify(cachedIssuer), cachedIssuerBefore);
});

test('registry-only issuer lookup preserves the signed data and returns an independent copy', async t => {
    mockFetch(t, async () => { throw new Error('Verified registry issuer is already cached'); });
    const registry = new Registry();
    const cachedIssuer = cacheIssuer(registry, [entry(issuer)]);
    const expected = structuredClone(cachedIssuer);
    const result = await registry.getIssuerFromX509AKI(aki);
    assert.deepEqual(result, expected);
    result.display.name = 'Modified';
    result.certificates[0].trust_lists.push('modified');
    assert.deepEqual(await registry.getIssuerFromX509AKI(aki), expected);
    assert.deepEqual(cachedIssuer, expected);
});

test('requested trust lists filter registry certificates while user certificates bypass that filter', async () => {
    const registry = new Registry({ trustedIssuerCertificates: [issuer.pem] });
    cacheIssuer(registry, [entry(renewedIssuer, [TrustList.UV]), entry(expiredIssuer, [TrustList.AAMVA_DTS])]);
    const result = await registry.resolveCertificateTrust(leaf, { trustLists: [TrustList.AAMVA_DTS] });

    assert.equal(result.trusted, true);
    assert.equal(result.issuer.certificates[0].trusted, true);
    assert.deepEqual(result.issuer.certificates[1].untrustedReasons, [UntrustedReason.ISSUER_CERTIFICATE_NOT_IN_TRUST_LISTS]);
    assert.deepEqual(result.issuer.certificates[2].untrustedReasons, [UntrustedReason.ISSUER_CERTIFICATE_EXPIRED]);
});

test('trust scope applies to all issuer certificates and is optional', async () => {
    const registry = new Registry({ trustedIssuerCertificates: [issuer.pem] });
    const result = await registry.resolveCertificateTrust(leaf, { trustScope: TrustScope.GOVERNMENT_ISSUED_ID });
    assert.equal(result.trusted, false);
    assert.deepEqual(result.untrustedReasons, [UntrustedReason.ISSUER_MISSING_REQUIRED_TRUST_SCOPE]);
    assert.deepEqual(result.issuer.certificates[0].untrustedReasons, result.untrustedReasons);
    assert.equal('untrustedReasons' in result.issuer, false);
    const withoutScope = await registry.resolveCertificateTrust(leaf);
    assert.equal(withoutScope.trusted, true);
    assert.deepEqual(await registry.resolveCertificateTrust(leaf, { trustScope: undefined }), withoutScope);
    assert.deepEqual(await registry.resolveCertificateTrust(leaf, { trustScope: null }), withoutScope);
});

test('selects any trusted certificate regardless of its position', async () => {
    const registry = new Registry({ trustedIssuerCertificates: [expiredIssuer.pem, issuer.pem] });
    const result = await registry.resolveCertificateTrust(leaf);
    assert.equal(result.trusted, true);
    assert.equal(result.issuer.certificates[0].trusted, false);
    assert.equal(result.issuer.certificates[1].trusted, true);
    assert.equal('untrustedReasons' in result, false);
});

test('selects the fewest reasons and uses original order for ties', async () => {
    const registry = new Registry();
    const otherExpiredIssuer = await createIssuer({ keyPair: issuer.keyPair, serial: 6, notAfter: EXPIRED });
    cacheIssuer(registry, [
        entry(expiredIssuer, [TrustList.AAMVA_DTS]),
        entry(futureIssuer),
        entry(otherExpiredIssuer),
    ]);
    const result = await registry.resolveCertificateTrust(leaf, { trustLists: [TrustList.UV] });
    assert.equal(result.trusted, false);
    assert.deepEqual(result.untrustedReasons, [UntrustedReason.ISSUER_CERTIFICATE_NOT_YET_VALID]);
    assert.deepEqual(result.issuer.certificates[0].untrustedReasons, [
        UntrustedReason.ISSUER_CERTIFICATE_EXPIRED,
        UntrustedReason.ISSUER_CERTIFICATE_NOT_IN_TRUST_LISTS,
    ]);
});

test('registry failures are ignored only when a user certificate is trusted', async t => {
    let calls = 0;
    mockFetch(t, async () => { calls++; throw new Error('Network unavailable'); });
    const options = { trustLists: [TrustList.UV] };
    const trustedRegistry = new Registry({ trustedIssuerCertificates: [issuer.pem] });
    const trustedResult = await trustedRegistry.resolveCertificateTrust(leaf, options);
    assert.equal(trustedResult.trusted, true);
    assert.equal('untrustedReasons' in trustedResult, false);
    assert.equal('untrustedReasons' in trustedResult.issuer, false);

    const expiredRegistry = new Registry({ trustedIssuerCertificates: [expiredIssuer.pem] });
    const expiredResult = await expiredRegistry.resolveCertificateTrust(leaf, options);
    assert.deepEqual(expiredResult.untrustedReasons, [UntrustedReason.ISSUER_CERTIFICATE_EXPIRED, UntrustedReason.ISSUER_FETCH_FAILED]);
    assert.equal('untrustedReasons' in expiredResult.issuer, false);
    assert.deepEqual(expiredResult.issuer.certificates[0].untrustedReasons, [UntrustedReason.ISSUER_CERTIFICATE_EXPIRED]);

    const missingResult = await new Registry().resolveCertificateTrust(leaf, options);
    assert.deepEqual(missingResult, {
        trusted: false,
        untrustedReasons: [UntrustedReason.ISSUER_CERTIFICATE_NOT_FOUND, UntrustedReason.ISSUER_FETCH_FAILED],
    });
    assert.equal(calls, 3);
});

test('leaf validity does not add a fetch failure when a local certificate is trusted', async t => {
    mockFetch(t, async () => ({ ok: false, status: 503 }));
    const registry = new Registry({ trustedIssuerCertificates: [issuer.pem] });
    const result = await registry.resolveCertificateTrust(await createLeaf({ notAfter: EXPIRED }), { trustLists: [TrustList.UV] });
    assert.deepEqual(result.untrustedReasons, [UntrustedReason.CERTIFICATE_EXPIRED]);
    assert.equal('untrustedReasons' in result.issuer, false);
});

test('signature mismatch skips CRL checks even in required mode', async t => {
    mockFetch(t, async () => { throw new Error('CRL must not be requested'); });
    const registry = new Registry({
        trustedIssuerCertificates: [mismatchedIssuer.pem],
        revocationCheckMode: RevocationCheckMode.REQUIRED,
    });
    const result = await registry.resolveCertificateTrust(leaf);
    assert.equal(result.trusted, false);
    assert.deepEqual(result.untrustedReasons, [UntrustedReason.CERTIFICATE_SIGNATURE_VERIFICATION_FAILED]);
    assert.equal(result.issuer.certificates[0].revocationStatus, 'not_checked');
});

test('matching public key with a different issuer name is not treated as the issuing certificate', async () => {
    const renamedIssuer = await createIssuer({ keyPair: issuer.keyPair, name: 'Different issuer' });
    const registry = new Registry({ trustedIssuerCertificates: [renamedIssuer.pem] });
    const result = await registry.resolveCertificateTrust(leaf);
    assert.deepEqual(result.untrustedReasons, [UntrustedReason.CERTIFICATE_SIGNATURE_VERIFICATION_FAILED]);
});

test('signature validation supports RSA and certificates signed with a different hash from their curve size', async () => {
    for(const algorithm of [
        { name: 'RSASSA-PKCS1-v1_5', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' },
        { name: 'ECDSA', namedCurve: 'P-384' },
    ]) {
        const keyPair = await crypto.subtle.generateKey(algorithm, true, ['sign', 'verify']);
        const signingIssuer = await createIssuer({ keyPair });
        const certificate = await createLeaf({ issuer: signingIssuer });
        const registry = new Registry({ trustedIssuerCertificates: [signingIssuer.pem] });
        assert.equal((await registry.resolveCertificateTrust(certificate)).trusted, true);
    }
});

test('skip mode does not fetch a CRL', async t => {
    mockFetch(t, async () => { throw new Error('CRL must not be requested'); });
    const registry = new Registry({ trustedIssuerCertificates: [issuer.pem] });
    assert.equal((await registry.resolveCertificateTrust(leaf)).trusted, true);
});

test('best effort permits failed CRL checks while required reports undetermined status', async t => {
    mockFetch(t, async () => { throw new Error('CRL unavailable'); });
    for(const mode of [RevocationCheckMode.BEST_EFFORT, RevocationCheckMode.REQUIRED]) {
        const registry = new Registry({ trustedIssuerCertificates: [issuer.pem], revocationCheckMode: mode });
        const result = await registry.resolveCertificateTrust(leaf);
        assert.equal(result.trusted, mode === RevocationCheckMode.BEST_EFFORT);
        assert.equal(result.issuer.certificates[0].revocationStatus, 'not_checked');
        if(mode === RevocationCheckMode.REQUIRED) {
            assert.deepEqual(result.untrustedReasons, [UntrustedReason.REVOCATION_STATUS_UNDETERMINED]);
        } else {
            assert.equal('untrustedReasons' in result, false);
        }
    }
});

test('missing distribution points are undetermined only in required mode', async () => {
    const certificate = await createLeaf({ crlUrls: [] });
    for(const mode of [RevocationCheckMode.BEST_EFFORT, RevocationCheckMode.REQUIRED]) {
        const registry = new Registry({ trustedIssuerCertificates: [issuer.pem], revocationCheckMode: mode });
        const result = await registry.resolveCertificateTrust(certificate);
        assert.equal(result.trusted, mode === RevocationCheckMode.BEST_EFFORT);
        assert.equal(result.issuer.certificates[0].revocationStatus, 'not_checked');
    }
});

test('verified CRLs report non-revoked and revoked states in both checking modes', async t => {
    let crl = await createCRL();
    mockFetch(t, async url => {
        assert.equal(url, CRL_URL);
        return { ok: true, arrayBuffer: async () => crl };
    });
    for(const revoked of [false, true]) {
        crl = await createCRL({ revoked });
        for(const mode of [RevocationCheckMode.BEST_EFFORT, RevocationCheckMode.REQUIRED]) {
            const registry = new Registry({ trustedIssuerCertificates: [issuer.pem], revocationCheckMode: mode });
            const result = await registry.resolveCertificateTrust(leaf);
            assert.equal(result.trusted, !revoked);
            assert.equal(result.issuer.certificates[0].revocationStatus, revoked ? 'revoked' : 'not_revoked');
            if(revoked) assert.deepEqual(result.untrustedReasons, [UntrustedReason.CERTIFICATE_REVOKED]);
        }
    }
});

test('removeFromCRL entries do not report revocation or establish non-revoked status', async t => {
    let crl;
    mockFetch(t, async () => new Response(crl));
    for(const delta of [true, false]) {
        crl = await createCRL({ revoked: true, revocationReason: 8, delta });
        for(const mode of [RevocationCheckMode.BEST_EFFORT, RevocationCheckMode.REQUIRED]) {
            const registry = new Registry({ trustedIssuerCertificates: [issuer.pem], revocationCheckMode: mode });
            const result = await registry.resolveCertificateTrust(leaf);
            assert.equal(result.trusted, mode === RevocationCheckMode.BEST_EFFORT);
            assert.equal(result.issuer.certificates[0].revocationStatus, 'not_checked');
            assert.deepEqual(result.untrustedReasons, mode === RevocationCheckMode.REQUIRED
                ? [UntrustedReason.REVOCATION_STATUS_UNDETERMINED]
                : undefined);
        }
    }
});

test('ordinary revocation reasons are recognized in complete and delta CRLs', async t => {
    let crl;
    mockFetch(t, async () => new Response(crl));
    for(const delta of [false, true]) {
        crl = await createCRL({ revoked: true, revocationReason: 1, delta });
        for(const mode of [RevocationCheckMode.BEST_EFFORT, RevocationCheckMode.REQUIRED]) {
            const registry = new Registry({ trustedIssuerCertificates: [issuer.pem], revocationCheckMode: mode });
            const result = await registry.resolveCertificateTrust(leaf);
            assert.equal(result.trusted, false);
            assert.equal(result.issuer.certificates[0].revocationStatus, 'revoked');
            assert.deepEqual(result.untrustedReasons, [UntrustedReason.CERTIFICATE_REVOKED]);
        }
    }
});

test('delta CRLs without a matching entry cannot establish non-revoked status', async t => {
    const crl = await createCRL({ delta: true });
    mockFetch(t, async () => new Response(crl));
    const registry = new Registry({ trustedIssuerCertificates: [issuer.pem], revocationCheckMode: RevocationCheckMode.REQUIRED });
    const result = await registry.resolveCertificateTrust(leaf);
    assert.equal(result.issuer.certificates[0].revocationStatus, 'not_checked');
    assert.deepEqual(result.untrustedReasons, [UntrustedReason.REVOCATION_STATUS_UNDETERMINED]);
});

test('concurrent certificate evaluations and resolver calls share CRL requests with caching disabled', async t => {
    const crl = await createCRL();
    let calls = 0;
    mockFetch(t, async () => {
        calls++;
        await new Promise(resolve => setTimeout(resolve, 10));
        return { ok: true, arrayBuffer: async () => crl };
    });
    const registry = new Registry({
        cacheEnabled: false,
        trustedIssuerCertificates: [issuer.pem, renewedIssuer.pem],
        revocationCheckMode: RevocationCheckMode.REQUIRED,
    });
    const results = await Promise.all([registry.resolveCertificateTrust(leaf), registry.resolveCertificateTrust(leaf)]);
    assert.equal(calls, 1);
    for(const result of results) {
        assert.equal(result.trusted, true);
        assert.deepEqual(result.issuer.certificates.map(certificate => certificate.revocationStatus), ['not_revoked', 'not_revoked']);
    }
    assert.equal(registry._cachedFetcher._inFlight.size, 0);
    assert.equal(registry._cachedFetcher._cache.size, 0);
    await registry.resolveCertificateTrust(leaf);
    assert.equal(calls, 2);
});

test('CRL cache uses the registry cache TTL and repeated resolver calls reuse it', async t => {
    const crl = await createCRL();
    let calls = 0;
    mockFetch(t, async () => {
        calls++;
        return { ok: true, arrayBuffer: async () => crl };
    });
    const registry = new Registry({
        cacheTTL: 60000,
        trustedIssuerCertificates: [issuer.pem],
        revocationCheckMode: RevocationCheckMode.REQUIRED,
    });
    let now = Date.now();
    t.mock.method(Date, 'now', () => now);
    assert.equal((await registry.resolveCertificateTrust(leaf)).trusted, true);
    now += 59999;
    assert.equal((await registry.resolveCertificateTrust(leaf)).trusted, true);
    assert.equal(calls, 1);
    now++;
    assert.equal((await registry.resolveCertificateTrust(leaf)).trusted, true);
    assert.equal(calls, 2);
});

test('a CRL failing one issuer signature check is cached and validated independently for another issuer', async t => {
    const crl = await createCRL();
    let calls = 0;
    mockFetch(t, async () => {
        calls++;
        return { ok: true, arrayBuffer: async () => crl };
    });
    const registry = new Registry({
        trustedIssuerCertificates: [mismatchedIssuer.pem, issuer.pem],
        revocationCheckMode: RevocationCheckMode.REQUIRED,
    });
    const otherLeaf = await createLeaf({ issuer: mismatchedIssuer });
    const invalid = await registry.resolveCertificateTrust(otherLeaf);
    assert.equal(invalid.trusted, false);
    assert.deepEqual(invalid.untrustedReasons, [UntrustedReason.REVOCATION_STATUS_UNDETERMINED]);
    const valid = await registry.resolveCertificateTrust(leaf);
    assert.equal(valid.trusted, true);
    assert.equal(valid.issuer.certificates[1].revocationStatus, 'not_revoked');
    assert.equal((await registry.resolveCertificateTrust(otherLeaf)).trusted, false);
    assert.equal(calls, 1);
});

test('cached malformed and not-yet-valid CRLs remain undetermined without repeated downloads', async t => {
    let body = new TextEncoder().encode('Not a CRL').buffer;
    let calls = 0;
    mockFetch(t, async () => {
        calls++;
        return { ok: true, arrayBuffer: async () => body };
    });
    for(const crl of [body, await createCRL({ thisUpdate: FUTURE })]) {
        body = crl;
        const registry = new Registry({
            trustedIssuerCertificates: [issuer.pem],
            revocationCheckMode: RevocationCheckMode.REQUIRED,
        });
        for(let attempt = 0; attempt < 2; attempt++) {
            const result = await registry.resolveCertificateTrust(leaf);
            assert.equal(result.trusted, false);
            assert.deepEqual(result.untrustedReasons, [UntrustedReason.REVOCATION_STATUS_UNDETERMINED]);
            assert.equal(result.issuer.certificates[0].revocationStatus, 'not_checked');
        }
    }
    assert.equal(calls, 2);
});

test('failed shared CRL requests are removed so subsequent calls can retry', async t => {
    const crl = await createCRL();
    let calls = 0;
    mockFetch(t, async () => {
        calls++;
        await new Promise(resolve => setTimeout(resolve, 10));
        if(calls === 1) throw new Error('Temporary CRL failure');
        return { ok: true, arrayBuffer: async () => crl };
    });
    const registry = new Registry({
        trustedIssuerCertificates: [issuer.pem, renewedIssuer.pem],
        revocationCheckMode: RevocationCheckMode.REQUIRED,
    });
    const failed = await registry.resolveCertificateTrust(leaf);
    assert.equal(calls, 1);
    assert.deepEqual(failed.untrustedReasons, [UntrustedReason.REVOCATION_STATUS_UNDETERMINED]);
    assert.equal(registry._cachedFetcher._inFlight.size, 0);
    assert.equal((await registry.resolveCertificateTrust(leaf)).trusted, true);
    assert.equal(calls, 2);
});

test('required CRL checks honor the configured request timeout', async t => {
    mockFetch(t, async (_url, { signal }) => new Promise((_resolve, reject) => {
        signal.addEventListener('abort', () => reject(new DOMException('Aborted', 'AbortError')));
    }));
    const registry = new Registry({
        trustedIssuerCertificates: [issuer.pem],
        revocationCheckMode: RevocationCheckMode.REQUIRED,
        timeout: 1,
    });
    const result = await registry.resolveCertificateTrust(leaf);
    assert.deepEqual(result.untrustedReasons, [UntrustedReason.REVOCATION_STATUS_UNDETERMINED]);
    assert.equal(registry._cachedFetcher._inFlight.size, 0);
});

test('exported certificate helpers round-trip PEM and verify across PKIjs copies', async () => {
    const leafPem = certificateToPem(leaf);
    for(const filename of SDK_VARIANTS) {
        const {
            certificateToPem: serialize,
            parsePemCertificate: parse,
            verifyCertificateSignature: verify,
        } = await import(`../build/${filename}`);
        const sdkCertificate = parse(leafPem);
        const sdkIssuer = parse(issuer.pem);
        const sdkMismatchedIssuer = parse(mismatchedIssuer.pem);

        if(filename.includes('bundled')) assert.notEqual(sdkCertificate.constructor, leaf.constructor, filename);
        assert.equal(serialize(leaf), leafPem, filename);
        assert.equal(serialize(sdkCertificate), leafPem, filename);
        assert.equal(certificateToPem(sdkCertificate), leafPem, filename);

        for(const verifySignature of [verify, verifyCertificateSignature]) {
            for(const certificate of [leaf, sdkCertificate, leafPem]) {
                for(const issuerCertificate of [issuer.certificate, sdkIssuer, issuer.pem]) {
                    assert.equal(await verifySignature(certificate, issuerCertificate), true, filename);
                }
                for(const issuerCertificate of [mismatchedIssuer.certificate, sdkMismatchedIssuer, mismatchedIssuer.pem]) {
                    assert.equal(await verifySignature(certificate, issuerCertificate), false, filename);
                }
            }
        }
    }
});

test('built SDK variants accept PEM and consumer-parsed PKIjs certificates, including revocation', async t => {
    let crl = await createCRL();
    mockFetch(t, async () => ({ ok: true, arrayBuffer: async () => crl }));
    for(const filename of SDK_VARIANTS) {
        const { Registry: BuiltRegistry, UntrustedReason: BuiltUntrustedReason } = await import(`../build/${filename}`);
        assert.deepEqual(BuiltUntrustedReason, UntrustedReason, filename);
        crl = await createCRL();
        const registry = new BuiltRegistry({
            cacheEnabled: false,
            trustedIssuerCertificates: [issuer.pem],
            revocationCheckMode: RevocationCheckMode.REQUIRED,
        });
        assert.equal((await registry.resolveCertificateTrust(leaf)).trusted, true, filename);
        assert.equal((await registry.resolveCertificateTrust(certificateToPem(leaf))).trusted, true, filename);
        crl = await createCRL({ revoked: true });
        const revoked = await registry.resolveCertificateTrust(leaf);
        assert.equal(revoked.trusted, false, filename);
        assert.deepEqual(revoked.untrustedReasons, ['certificate_revoked'], filename);
        assert.deepEqual(revoked.issuer.certificates[0].untrustedReasons, ['certificate_revoked'], filename);
        crl = await createCRL({ revoked: true, revocationReason: 8, delta: true });
        const removed = await registry.resolveCertificateTrust(leaf);
        assert.equal(removed.trusted, false, filename);
        assert.equal(removed.issuer.certificates[0].revocationStatus, 'not_checked', filename);
        assert.deepEqual(removed.untrustedReasons, ['revocation_status_undetermined'], filename);
    }
});

test('built SDK variants bound their caches and preserve recently used issuer responses', async t => {
    mockFetch(t, async () => new Response(null, { status: 404 }));
    for(const filename of SDK_VARIANTS) {
        const { Registry: BuiltRegistry } = await import(`../build/${filename}`);
        const registry = new BuiltRegistry();
        for(let i = 0; i < 1024; i++) await registry.getIssuerFromX509AKI(`missing-${i}`);
        await registry.getIssuerFromX509AKI('missing-0');
        await registry.getIssuerFromX509AKI('missing-1024');
        const cache = registry._cachedFetcher._cache;
        assert.equal(cache.size, 1024, filename);
        assert.equal(cache.has(`issuer:${REGISTRY_URL_BASE}/issuers/x509_aki/missing-0.json`), true, filename);
        assert.equal(cache.has(`issuer:${REGISTRY_URL_BASE}/issuers/x509_aki/missing-1.json`), false, filename);
    }
});

function mockFetch(t, implementation) {
    t.mock.method(globalThis, 'fetch', implementation);
}

function entry(source, trustLists = [TrustList.UV]) {
    return { data: source.pem, format: 'pem', trust_lists: trustLists };
}

function cacheIssuer(registry, certificates) {
    const registryIssuer = {
        issuer_id: `x509_aki:${aki}`,
        entity_type: 'government',
        entity_metadata: { country: 'US', region: 'VA' },
        display: { name: 'Registry name', logo: 'https://example.test/logo.png' },
        trust_scopes: [TrustScope.GOVERNMENT_ISSUED_ID],
        certificates,
        signature: 'Already verified before caching',
    };
    registry._cachedFetcher._cache.set(`issuer:${REGISTRY_URL_BASE}/issuers/x509_aki/${aki}.json`, {
        value: { ok: true, issuer: registryIssuer },
        expiresAt: Date.now() + 60000,
    });
    return registryIssuer;
}

async function generateKeyPair() {
    return crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
}

function extension(oid, value, critical = false) {
    return new Extension({ extnID: oid, critical, extnValue: value.toSchema ? value.toSchema().toBER() : value.toBER() });
}

function name(value) {
    return new RelativeDistinguishedNames({ typesAndValues: [
        new AttributeTypeAndValue({ type: '2.5.4.3', value: new asn1js.Utf8String({ value }) }),
        new AttributeTypeAndValue({ type: '2.5.4.6', value: new asn1js.PrintableString({ value: 'US' }) }),
    ] });
}

async function createIssuer(options = {}) {
    const keyPair = options.keyPair || await generateKeyPair();
    const subject = name(options.name || 'Test issuer');
    const certificate = new Certificate({
        version: 2,
        serialNumber: new asn1js.Integer({ value: options.serial || 1 }),
        subject,
        issuer: subject,
        notBefore: new Time({ type: 1, value: options.notBefore || VALID_FROM }),
        notAfter: new Time({ type: 1, value: options.notAfter || VALID_UNTIL }),
        extensions: [
            extension('2.5.29.14', new asn1js.OctetString({ valueHex: new Uint8Array([1, 2, 3, 4]).buffer })),
            extension('2.5.29.19', new BasicConstraints({ cA: true }), true),
            extension('2.5.29.15', new asn1js.BitString({ valueHex: new Uint8Array([0x06]).buffer, unusedBits: 1 }), true),
        ],
    });
    await certificate.subjectPublicKeyInfo.importKey(keyPair.publicKey);
    await certificate.sign(keyPair.privateKey, 'SHA-256');
    const pem = certificateToPem(certificate);
    return { certificate: parsePemCertificate(pem), pem, keyPair };
}

async function createLeaf(options = {}) {
    const signingIssuer = options.issuer || issuer;
    const extensions = [];
    if(options.includeAKI !== false) {
        extensions.push(extension('2.5.29.35', new AuthorityKeyIdentifier({
            keyIdentifier: new asn1js.OctetString({ valueHex: new Uint8Array([1, 2, 3, 4]).buffer }),
        })));
    }
    const urls = options.crlUrls || [CRL_URL];
    if(urls.length > 0) {
        extensions.push(extension('2.5.29.31', new CRLDistributionPoints({
            distributionPoints: [new DistributionPoint({
                distributionPoint: urls.map(value => new GeneralName({ type: 6, value })),
            })],
        })));
    }
    const certificate = new Certificate({
        version: 2,
        serialNumber: new asn1js.Integer({ value: 100 }),
        subject: name('Document signer'),
        issuer: signingIssuer.certificate.subject,
        notBefore: new Time({ type: 1, value: options.notBefore || VALID_FROM }),
        notAfter: new Time({ type: 1, value: options.notAfter || VALID_UNTIL }),
        extensions,
    });
    await certificate.subjectPublicKeyInfo.importKey(leafKeyPair.publicKey);
    await certificate.sign(signingIssuer.keyPair.privateKey, 'SHA-256');
    return parsePemCertificate(certificateToPem(certificate));
}

async function createCRL(options = {}) {
    const crl = new CertificateRevocationList({
        version: 1,
        issuer: issuer.certificate.subject,
        thisUpdate: new Time({ type: 1, value: options.thisUpdate || VALID_FROM }),
        nextUpdate: new Time({ type: 1, value: VALID_UNTIL }),
        ...(options.delta && { crlExtensions: new Extensions({ extensions: [
            extension('2.5.29.27', new asn1js.Integer({ value: 1 }), true),
            extension('2.5.29.20', new asn1js.Integer({ value: 2 })),
            extension('2.5.29.35', new AuthorityKeyIdentifier({
                keyIdentifier: new asn1js.OctetString({ valueHex: new Uint8Array([1, 2, 3, 4]).buffer }),
            })),
        ] }) }),
        revokedCertificates: options.revoked ? [new RevokedCertificate({
            userCertificate: leaf.serialNumber,
            revocationDate: new Time({ type: 1, value: VALID_FROM }),
            ...(options.revocationReason !== undefined && { crlEntryExtensions: new Extensions({ extensions: [
                extension('2.5.29.21', new asn1js.Enumerated({ value: options.revocationReason })),
            ] }) }),
        })] : [],
    });
    await crl.sign(issuer.keyPair.privateKey, 'SHA-256');
    return crl.toSchema().toBER();
}
