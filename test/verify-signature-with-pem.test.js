import { before, test } from 'node:test';
import assert from 'node:assert/strict';
import * as asn1js from 'asn1js';
import { AttributeTypeAndValue, Certificate, RelativeDistinguishedNames, Time, createCMSECDSASignature } from 'pkijs';
import { certificateToPem, verifySignatureWithPem } from '../scripts/trusted-issuer-registry.js';
import { ensurePKIjsCryptoEngine } from '../scripts/certificate-helper.js';
import { base64ToUint8Array, uint8ArrayToBase64 } from '../scripts/utils.js';

const DATA = new TextEncoder().encode('Signature verification regression test');
const FIXTURES = [];
const SDK_VARIANTS = [
    '../scripts/trusted-issuer-registry.js',
    '../build/trusted-issuer-registry.js',
    '../build/trusted-issuer-registry.min.js',
    '../build/trusted-issuer-registry.bundled.js',
    '../build/trusted-issuer-registry.bundled.min.js',
];

before(async () => {
    ensurePKIjsCryptoEngine();
    for(const [namedCurve, hash, override] of [
        ['P-256', 'SHA-256', 'SHA-384'],
        ['P-384', 'SHA-384', 'SHA-512'],
        ['P-521', 'SHA-512', 'SHA-256'],
    ]) {
        const keys = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve }, true, ['sign', 'verify']);
        const pem = await createCertificate(keys, 'SHA-256');
        FIXTURES.push(await createFixture(`ECDSA ${namedCurve} default hash`, keys, pem, hash));
        FIXTURES.push(await createFixture(`ECDSA ${namedCurve} overridden hash`, keys, pem, override, {
            hash: override,
        }));
    }
    for(const name of ['RSASSA-PKCS1-v1_5', 'RSA-PSS']) {
        for(const hash of ['SHA-256', 'SHA-384', 'SHA-512']) {
            const keys = await crypto.subtle.generateKey({
                name, hash, modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]),
            }, true, ['sign', 'verify']);
            const pem = await createCertificate(keys, hash);
            const options = name === 'RSA-PSS'
                ? { name, hash, saltLength: Number(hash.slice(4)) / 8 }
                : { name, hash };
            FIXTURES.push(await createFixture(`${name} ${hash}`, keys, pem, hash, options));
            if(name === 'RSA-PSS' && hash === 'SHA-256') {
                for(const saltLength of [0, 20]) {
                    FIXTURES.push(await createFixture(`RSA-PSS SHA-256 salt length ${saltLength}`, keys, pem, hash, {
                        name, hash, saltLength,
                    }));
                }
            }
        }
    }
});

for(const variant of SDK_VARIANTS) {
    test(`${variant}: data signatures use defaults or explicit parameters`, async t => {
        const { verifySignatureWithPem: verify } = await import(variant);
        for(const fixture of FIXTURES) {
            await t.test(fixture.label, async () => {
                assert.equal(await verify(fixture.pem, fixture.signature, DATA, fixture.options), true);
                assert.equal(await verify(fixture.pem, fixture.signature, DATA.buffer, fixture.options), true);

                const framed = new Uint8Array(DATA.length + 8);
                framed.set(DATA, 3);
                const view = new DataView(framed.buffer, 3, DATA.length);
                assert.equal(await verify(fixture.pem, fixture.signature, view, fixture.options), true);
                assert.equal(await verify(fixture.pem, fixture.signature, framed.subarray(3, 3 + DATA.length), fixture.options), true);

                const changedData = DATA.slice();
                changedData[0] ^= 1;
                assert.equal(await verify(fixture.pem, fixture.signature, changedData, fixture.options), false);
                const changedSignature = base64ToUint8Array(fixture.signature);
                changedSignature[changedSignature.length - 1] ^= 1;
                assert.equal(await verify(fixture.pem, uint8ArrayToBase64(changedSignature), DATA, fixture.options), false);
            });
        }
    });
}

test('RSA requires explicit algorithm and hash before importing the key', async t => {
    t.mock.method(console, 'error', () => {});
    const importKey = t.mock.method(crypto.subtle, 'importKey');
    const fixture = FIXTURES.find(value => value.label === 'RSASSA-PKCS1-v1_5 SHA-256');
    for(const options of [
        undefined,
        {},
        { hash: 'SHA-256' },
        { name: 'RSASSA-PKCS1-v1_5' },
        { name: 'RSASSA-PKCS1-v1_5', hash: undefined },
        { name: 'ECDSA', hash: 'SHA-256' },
        { name: 'RSASSA-PSS', hash: 'SHA-256', saltLength: 32 },
    ]) {
        await assert.rejects(verifySignatureWithPem(fixture.pem, fixture.signature, DATA, options),
            /RSA signatures require explicit name and hash options/);
    }
    assert.equal(importKey.mock.callCount(), 0);
});

test('RSA-PSS requires an explicit non-negative integer salt length', async t => {
    t.mock.method(console, 'error', () => {});
    const importKey = t.mock.method(crypto.subtle, 'importKey');
    const fixture = FIXTURES.find(value => value.label === 'RSA-PSS SHA-256');
    for(const saltLength of [undefined, null, -1, 1.5, NaN, Infinity, '32']) {
        await assert.rejects(verifySignatureWithPem(fixture.pem, fixture.signature, DATA, {
            name: 'RSA-PSS', hash: 'SHA-256', saltLength,
        }), /RSA-PSS signatures require a non-negative integer saltLength/);
    }
    assert.equal(importKey.mock.callCount(), 0);
});

test('EC certificates reject RSA algorithms', async t => {
    t.mock.method(console, 'error', () => {});
    const fixture = FIXTURES[0];
    for(const name of ['RSASSA-PKCS1-v1_5', 'RSA-PSS']) {
        await assert.rejects(verifySignatureWithPem(fixture.pem, fixture.signature, DATA, {
            name, hash: 'SHA-256', saltLength: 32,
        }), /EC certificates require the ECDSA signature algorithm/);
    }
});

test('explicit ECDSA name and hash identifier objects are supported', async () => {
    const fixture = FIXTURES.find(value => value.label === 'ECDSA P-256 overridden hash');
    assert.equal(await verifySignatureWithPem(fixture.pem, fixture.signature, DATA, {
        name: 'ECDSA', hash: { name: 'SHA-384' },
    }), true);
    const rsa = FIXTURES.find(value => value.label === 'RSASSA-PKCS1-v1_5 SHA-256');
    assert.equal(await verifySignatureWithPem(rsa.pem, rsa.signature, DATA, {
        name: 'RSASSA-PKCS1-v1_5', hash: { name: 'SHA-256' },
    }), true);
});

test('incorrect parameters return false without retrying other combinations', async t => {
    const verify = t.mock.method(crypto.subtle, 'verify');
    for(const [label, options] of [
        ['ECDSA P-256 default hash', { hash: 'SHA-512' }],
        ['RSASSA-PKCS1-v1_5 SHA-256', { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-384' }],
        ['RSA-PSS SHA-256', { name: 'RSA-PSS', hash: 'SHA-256', saltLength: 0 }],
        ['RSA-PSS SHA-256', { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }],
    ]) {
        const fixture = FIXTURES.find(value => value.label === label);
        assert.equal(await verifySignatureWithPem(fixture.pem, fixture.signature, DATA, options), false);
    }
    assert.equal(verify.mock.callCount(), 4);
});

test('malformed input and unsupported hashes reject the promise', async t => {
    t.mock.method(console, 'error', () => {});
    await assert.rejects(verifySignatureWithPem('not a certificate', '', DATA));
    const fixture = FIXTURES[0];
    await assert.rejects(verifySignatureWithPem(fixture.pem, fixture.signature, DATA, { hash: 'unsupported' }));
});

test('ECDSA conversion rejects malformed DER signatures in every build', async t => {
    t.mock.method(console, 'error', () => {});
    const fixture = FIXTURES[0];
    const valid = base64ToUint8Array(fixture.signature);
    const trailing = new Uint8Array(valid.length + 1);
    trailing.set(valid);
    const malformed = [
        new Uint8Array(),
        valid.subarray(0, valid.length - 1),
        trailing,
        new Uint8Array(new asn1js.Integer({ value: 1 }).toBER()),
        new Uint8Array(new asn1js.Sequence({ value: [new asn1js.Integer({ value: 1 })] }).toBER()),
        new Uint8Array(new asn1js.Sequence({ value: [
            new asn1js.OctetString({ valueHex: new Uint8Array([1]) }), new asn1js.Integer({ value: 1 }),
        ] }).toBER()),
    ];
    for(const variant of SDK_VARIANTS) {
        const { verifySignatureWithPem: verify } = await import(variant);
        for(const bytes of malformed) {
            await assert.rejects(verify(fixture.pem, uint8ArrayToBase64(bytes), DATA), /Invalid DER signature structure/);
        }
    }
});

test('ECDSA conversion pads small integers but does not truncate oversized integers', async t => {
    t.mock.method(console, 'error', () => {});
    const small = new asn1js.Sequence({ value: [new asn1js.Integer({ value: 1 }), new asn1js.Integer({ value: 1 })] });
    const oversized = new asn1js.Sequence({ value: [
        new asn1js.Integer({ valueHex: new Uint8Array(33).fill(1) }), new asn1js.Integer({ value: 1 }),
    ] });
    for(const variant of SDK_VARIANTS) {
        const { verifySignatureWithPem: verify } = await import(variant);
        for(const fixture of FIXTURES.filter(value => value.label.endsWith('default hash'))) {
            assert.equal(await verify(fixture.pem, uint8ArrayToBase64(new Uint8Array(small.toBER())), DATA), false);
        }
        await assert.rejects(verify(FIXTURES[0].pem, uint8ArrayToBase64(new Uint8Array(oversized.toBER())), DATA));
    }
});

async function createCertificate(keys, hash) {
    const name = new RelativeDistinguishedNames({ typesAndValues: [new AttributeTypeAndValue({
        type: '2.5.4.3', value: new asn1js.Utf8String({ value: 'Signature test issuer' }),
    })] });
    const certificate = new Certificate({
        version: 2, serialNumber: new asn1js.Integer({ value: 1 }), issuer: name, subject: name,
        notBefore: new Time({ type: 1, value: new Date('2000-01-01T00:00:00Z') }),
        notAfter: new Time({ type: 1, value: new Date('2100-01-01T00:00:00Z') }),
    });
    await certificate.subjectPublicKeyInfo.importKey(keys.publicKey);
    await certificate.sign(keys.privateKey, hash);
    return certificateToPem(certificate);
}

async function createFixture(label, keys, pem, hash, options) {
    const algorithm = keys.privateKey.algorithm.name === 'RSA-PSS'
        ? { name: 'RSA-PSS', saltLength: options.saltLength }
        : { name: keys.privateKey.algorithm.name, hash };
    const signature = await crypto.subtle.sign(algorithm, keys.privateKey, DATA);
    assert.equal(await crypto.subtle.verify(algorithm, keys.publicKey, signature, DATA), true);
    const encodedSignature = algorithm.name === 'ECDSA' ? createCMSECDSASignature(signature) : signature;
    return {
        label, pem, options: options && Object.freeze(options),
        signature: uint8ArrayToBase64(new Uint8Array(encodedSignature)),
    };
}
