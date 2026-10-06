import { before, test } from 'node:test';
import assert from 'node:assert/strict';
import * as asn1js from 'asn1js';
import {
    AlgorithmIdentifier, AttributeTypeAndValue, AuthorityKeyIdentifier, Certificate, CertificateRevocationList,
    CRLDistributionPoints, DistributionPoint, Extension, GeneralName, RelativeDistinguishedNames, RSASSAPSSParams, Time,
} from 'pkijs';
import { certificateToPem, ensurePKIjsCryptoEngine, parsePemCertificate, verifySignedData } from '../scripts/certificate-helper.js';
import { uint8ArrayToBase64 } from '../scripts/utils.js';

const DATA = new TextEncoder().encode('PSS-only public key regression test');
const PSS_OID = '1.2.840.113549.1.1.10';
const CRL_URL = 'https://example.test/pss.crl';
const IDENTIFIER = new Uint8Array([1, 2, 3, 4]);
const HASH_OIDS = { 'SHA-1': '1.3.14.3.2.26', 'SHA-256': '2.16.840.1.101.3.4.2.1', 'SHA-384': '2.16.840.1.101.3.4.2.2', 'SHA-512': '2.16.840.1.101.3.4.2.3' };
const VARIANTS = [
    '../scripts/trusted-issuer-registry.js',
    '../build/trusted-issuer-registry.js',
    '../build/trusted-issuer-registry.min.js',
    '../build/trusted-issuer-registry.bundled.js',
    '../build/trusted-issuer-registry.bundled.min.js',
];
const FIXTURES = [];

before(async () => {
    ensurePKIjsCryptoEngine();
    for(const hash of Object.keys(HASH_OIDS)) {
        const keys = await crypto.subtle.generateKey({
            name: 'RSA-PSS', hash, modulusLength: hash === 'SHA-384' ? 3072 : 2048, publicExponent: new Uint8Array([1, 0, 1]),
        }, true, ['sign', 'verify']);
        const saltLength = hash === 'SHA-1' ? 20 : Number(hash.slice(4)) / 8;
        const restrictions = hash === 'SHA-1' ? new RSASSAPSSParams() : pssParameters(hash, saltLength);
        const issuer = await createIssuer(keys, hash, restrictions);
        const leaf = await createLeaf(keys, hash, issuer);
        const crl = new CertificateRevocationList({
            version: 1, issuer: issuer.subject, thisUpdate: time('2000-01-01'), nextUpdate: time('2100-01-01'),
        });
        await crl.sign(keys.privateKey, hash);
        FIXTURES.push({ keys, hash, saltLength, issuer, leaf, crl });
    }
});

for(const variant of VARIANTS) {
    test(`${variant}: PSS-only keys verify data, certificates and CRLs`, async t => {
        const sdk = await import(variant);
        for(const fixture of FIXTURES) {
            await t.test(fixture.hash, async t => {
                const { keys, hash, saltLength, issuer, leaf, crl } = fixture;
                const pem = certificateToPem(issuer);
                for(const length of [saltLength, saltLength + 16]) {
                    const signature = await crypto.subtle.sign({ name: 'RSA-PSS', saltLength: length }, keys.privateKey, DATA);
                    const options = { name: 'RSA-PSS', hash, saltLength: length };
                    assert.equal(await sdk.verifySignatureWithPem(pem, uint8ArrayToBase64(new Uint8Array(signature)), DATA, options), true);
                    assert.equal(await sdk.verifySignatureWithPem(pem, uint8ArrayToBase64(new Uint8Array(signature)), new Uint8Array([0]), options), false);
                }
                assert.equal(await sdk.verifyCertificateSignature(issuer, issuer), true);
                assert.equal(await sdk.verifyCertificateSignature(leaf, issuer), true);
                const before = certificateToPem(issuer);
                let fetches = 0;
                t.mock.method(globalThis, 'fetch', async url => {
                    assert.equal(url, CRL_URL);
                    fetches++;
                    return new Response(crl.toSchema().toBER());
                });
                const registry = new sdk.Registry({ trustedIssuerCertificates: [pem], revocationCheckMode: sdk.RevocationCheckMode.REQUIRED });
                const result = await registry.resolveCertificateTrust(leaf);
                assert.equal(result.trusted, true);
                assert.equal(result.issuer.certificates[0].revocationStatus, 'not_revoked');
                assert.equal(fetches, 1);
                assert.equal(certificateToPem(issuer), before);
            });
        }
    });
}

test('PSS-only keys reject incompatible padding, hashes and salts before verification', async t => {
    t.mock.method(console, 'error', () => {});
    const fixture = FIXTURES.find(value => value.hash === 'SHA-256');
    const { keys, issuer } = fixture;
    const signature = uint8ArrayToBase64(new Uint8Array(await crypto.subtle.sign({ name: 'RSA-PSS', saltLength: 32 }, keys.privateKey, DATA)));
    for(const variant of VARIANTS) {
        const sdk = await import(variant);
        const verify = t.mock.method(crypto.subtle, 'verify');
        for(const options of [
            { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
            { name: 'RSA-PSS', hash: 'SHA-384', saltLength: 32 },
            { name: 'RSA-PSS', hash: 'SHA-256', saltLength: 20 },
        ]) {
            await assert.rejects(sdk.verifySignatureWithPem(certificateToPem(issuer), signature, DATA, options), /RSA-PSS/);
        }
        assert.equal(verify.mock.callCount(), 0);
        verify.mock.restore();
    }
});

test('PSS-only keys with absent parameters do not impose hash or salt restrictions', async () => {
    const { keys, hash, leaf } = FIXTURES.find(value => value.hash === 'SHA-256');
    const issuer = await createIssuer(keys, hash, null);
    const signature = uint8ArrayToBase64(new Uint8Array(await crypto.subtle.sign({ name: 'RSA-PSS', saltLength: 0 }, keys.privateKey, DATA)));
    for(const variant of VARIANTS) {
        const sdk = await import(variant);
        assert.equal(await sdk.verifySignatureWithPem(certificateToPem(issuer), signature, DATA, { name: 'RSA-PSS', hash, saltLength: 0 }), true);
        assert.equal(await sdk.verifyCertificateSignature(leaf, issuer), true);
    }
});

test('PSS signature and key restrictions reject unsupported MGF, trailer and salt parameters', async t => {
    t.mock.method(console, 'error', () => {});
    const { keys, hash, issuer, leaf } = FIXTURES.find(value => value.hash === 'SHA-256');
    for(const changes of [
        { maskGenAlgorithm: new AlgorithmIdentifier({ algorithmId: '1.2.840.113549.1.1.8', algorithmParams: hashAlgorithm('SHA-384').toSchema() }) },
        { maskGenAlgorithm: new AlgorithmIdentifier({ algorithmId: '1.2.3' }) },
        { trailerField: 2 },
        { saltLength: -1 },
    ]) {
        const parameters = pssParameters(hash, 32, changes);
        const algorithm = new AlgorithmIdentifier({ algorithmId: PSS_OID, algorithmParams: parameters.toSchema() });
        for(const publicKeyInfo of [issuer.subjectPublicKeyInfo, leaf.subjectPublicKeyInfo]) {
            await assert.rejects(verifySignedData(leaf.tbsView, leaf.signatureValue, publicKeyInfo, algorithm), /RSA-PSS/);
        }
        const restrictedIssuer = await createIssuer(keys, hash, parameters);
        for(const variant of VARIANTS) {
            const sdk = await import(variant);
            assert.equal(await sdk.verifyCertificateSignature(leaf, restrictedIssuer), false);
        }
    }
    const highMinimum = await createIssuer(keys, hash, pssParameters(hash, 64));
    for(const variant of VARIANTS) {
        const sdk = await import(variant);
        assert.equal(await sdk.verifyCertificateSignature(leaf, highMinimum), false);
        assert.equal(await sdk.verifyCertificateSignature(highMinimum, highMinimum), false);
    }
});

test('required revocation rejects a signed CRL with unsupported PSS parameters', async t => {
    const { keys, hash, issuer, leaf } = FIXTURES.find(value => value.hash === 'SHA-256');
    const parameters = pssParameters(hash, 32, {
        maskGenAlgorithm: new AlgorithmIdentifier({ algorithmId: '1.2.840.113549.1.1.8', algorithmParams: hashAlgorithm('SHA-384').toSchema() }),
    });
    const algorithm = new AlgorithmIdentifier({ algorithmId: PSS_OID, algorithmParams: parameters.toSchema() });
    const crl = new CertificateRevocationList({
        version: 1, issuer: issuer.subject, thisUpdate: time('2000-01-01'), nextUpdate: time('2100-01-01'),
        signature: algorithm, signatureAlgorithm: algorithm,
    });
    crl.tbsView = new Uint8Array(crl.encodeTBS().toBER());
    const signature = await crypto.subtle.sign({ name: 'RSA-PSS', saltLength: 32 }, keys.privateKey, crl.tbsView);
    assert.equal(await crypto.subtle.verify({ name: 'RSA-PSS', saltLength: 32 }, keys.publicKey, signature, crl.tbsView), true);
    crl.signatureValue = new asn1js.BitString({ valueHex: signature });
    t.mock.method(globalThis, 'fetch', async () => new Response(crl.toSchema().toBER()));
    for(const variant of VARIANTS) {
        const sdk = await import(variant);
        const registry = new sdk.Registry({ trustedIssuerCertificates: [certificateToPem(issuer)], revocationCheckMode: sdk.RevocationCheckMode.REQUIRED });
        const result = await registry.resolveCertificateTrust(leaf);
        assert.equal(result.trusted, false);
        assert.deepEqual(result.untrustedReasons, [sdk.UntrustedReason.REVOCATION_STATUS_UNDETERMINED]);
        assert.equal(result.issuer.certificates[0].revocationStatus, 'not_checked');
    }
});

function hashAlgorithm(hash) {
    return new AlgorithmIdentifier({ algorithmId: HASH_OIDS[hash], algorithmParams: new asn1js.Null() });
}

function pssParameters(hash, saltLength, changes = {}) {
    return new RSASSAPSSParams({
        hashAlgorithm: hashAlgorithm(hash),
        maskGenAlgorithm: new AlgorithmIdentifier({ algorithmId: '1.2.840.113549.1.1.8', algorithmParams: hashAlgorithm(hash).toSchema() }),
        saltLength, ...changes,
    });
}

function time(date) {
    return new Time({ type: 1, value: new Date(date) });
}

function name(value) {
    return new RelativeDistinguishedNames({ typesAndValues: [new AttributeTypeAndValue({
        type: '2.5.4.3', value: new asn1js.Utf8String({ value }),
    })] });
}

function extension(extnID, value) {
    return new Extension({ extnID, extnValue: value.toSchema ? value.toSchema().toBER() : value.toBER() });
}

async function createIssuer(keys, hash, restrictions) {
    const certificate = new Certificate({
        version: 2, serialNumber: new asn1js.Integer({ value: 1 }), subject: name('PSS issuer'), issuer: name('PSS issuer'),
        notBefore: time('2000-01-01'), notAfter: time('2100-01-01'),
        extensions: [extension('2.5.29.14', new asn1js.OctetString({ valueHex: IDENTIFIER })),
            extension('2.5.29.15', new asn1js.BitString({ valueHex: new Uint8Array([0x02]), unusedBits: 1 }))],
    });
    await certificate.subjectPublicKeyInfo.importKey(keys.publicKey);
    certificate.subjectPublicKeyInfo.algorithm = new AlgorithmIdentifier({
        algorithmId: PSS_OID, ...(restrictions && { algorithmParams: restrictions.toSchema() }),
    });
    await certificate.sign(keys.privateKey, hash);
    return parsePemCertificate(certificateToPem(certificate));
}

async function createLeaf(keys, hash, issuer) {
    const certificate = new Certificate({
        version: 2, serialNumber: new asn1js.Integer({ value: 2 }), subject: name('Document signer'), issuer: issuer.subject,
        notBefore: time('2000-01-01'), notAfter: time('2100-01-01'),
        extensions: [
            extension('2.5.29.35', new AuthorityKeyIdentifier({ keyIdentifier: new asn1js.OctetString({ valueHex: IDENTIFIER }) })),
            extension('2.5.29.31', new CRLDistributionPoints({ distributionPoints: [new DistributionPoint({
                distributionPoint: [new GeneralName({ type: 6, value: CRL_URL })],
            })] })),
        ],
    });
    await certificate.subjectPublicKeyInfo.importKey(keys.publicKey);
    await certificate.sign(keys.privateKey, hash);
    return parsePemCertificate(certificateToPem(certificate));
}
