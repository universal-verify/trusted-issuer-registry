import test from 'node:test';
import assert from 'node:assert/strict';
import { cpSync, mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync } from 'node:fs';
import { createRequire } from 'node:module';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import * as asn1js from 'asn1js';
import {
    AttributeTypeAndValue, AuthorityKeyIdentifier, Certificate, CertificateRevocationList, CRLDistributionPoints,
    DistributionPoint, Extension, Extensions, GeneralName, RelativeDistinguishedNames, RevokedCertificate, Time, createCMSECDSASignature,
} from 'pkijs';
import { certificateToPem, ensurePKIjsCryptoEngine } from '../scripts/certificate-helper.js';
import { uint8ArrayToBase64 } from '../scripts/utils.js';

const ROOT = fileURLToPath(new URL('../', import.meta.url));
const CRL_URL = 'https://example.test/separate-asn1.crl';
const DATA = new TextEncoder().encode('Separate ASN1.js copies');

test('separate ASN1.js and PKIjs copies preserve issuer trust, signatures and CRL checks', async t => {
    const directory = mkdtempSync(path.join(tmpdir(), 'trusted-issuer-separate-asn1-'));
    t.after(() => rmSync(directory, { recursive: true, force: true }));
    const modules = path.join(directory, 'node_modules');
    const library = path.join(modules, 'trusted-issuer-registry');
    mkdirSync(path.join(library, 'node_modules'), { recursive: true });
    for(const file of ['package.json', 'scripts', 'build']) cpSync(path.join(ROOT, file), path.join(library, file), { recursive: true });
    cpSync(path.join(ROOT, 'node_modules/pkijs'), path.join(modules, 'pkijs'), { recursive: true });
    for(const location of [path.join(library, 'node_modules/asn1js'), path.join(modules, 'pkijs/node_modules/asn1js')]) {
        cpSync(path.join(ROOT, 'node_modules/asn1js'), location, { recursive: true });
    }
    const dependencies = new Set(['pkijs', 'asn1js'].flatMap(dependency =>
        Object.keys(JSON.parse(readFileSync(path.join(ROOT, 'node_modules', dependency, 'package.json'))).dependencies)));
    for(const dependency of Object.keys(JSON.parse(readFileSync(path.join(ROOT, 'package.json'))).dependencies)) dependencies.add(dependency);
    for(const dependency of dependencies) {
        if(['pkijs', 'asn1js'].includes(dependency)) continue;
        mkdirSync(path.dirname(path.join(modules, dependency)), { recursive: true });
        symlinkSync(path.join(ROOT, 'node_modules', dependency), path.join(modules, dependency), 'junction');
    }
    const libraryRequire = createRequire(path.join(library, 'package.json'));
    const pkijsRequire = createRequire(path.join(modules, 'pkijs/package.json'));
    const libraryASN1 = libraryRequire('asn1js');
    const pkiASN1 = pkijsRequire('asn1js');
    assert.notEqual(libraryASN1.OctetString, pkiASN1.OctetString);
    const helpers = await import(pathToFileURL(path.join(library, 'scripts/certificate-helper.js')));

    ensurePKIjsCryptoEngine();
    const keys = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
    const subject = new RelativeDistinguishedNames({ typesAndValues: [new AttributeTypeAndValue({
        type: '2.5.4.3', value: new asn1js.Utf8String({ value: 'Separate-copy issuer' }),
    })] });
    const issuer = new Certificate({
        version: 2, serialNumber: new asn1js.Integer({ value: 1 }), subject, issuer: subject,
        notBefore: time('2000-01-01'), notAfter: time('2100-01-01'),
        extensions: [extension('2.5.29.14', new asn1js.OctetString({ valueHex: new Uint8Array([1, 2, 3, 4]) })),
            extension('2.5.29.15', new asn1js.BitString({ valueHex: new Uint8Array([0x02]), unusedBits: 1 }))],
    });
    await issuer.subjectPublicKeyInfo.importKey(keys.publicKey);
    await issuer.sign(keys.privateKey, 'SHA-256');
    const pem = certificateToPem(issuer);
    const parsed = helpers.parsePemCertificate(pem);
    assert.ok(parsed.extensions[0].parsedValue instanceof pkiASN1.OctetString);
    assert.ok(!(parsed.extensions[0].parsedValue instanceof libraryASN1.OctetString));
    assert.equal(helpers.getSubjectKeyIdentifier(parsed), 'AQIDBA');
    const { Extension: ForeignExtension } = libraryRequire('pkijs');
    const invalid = new ForeignExtension({
        extnID: '2.5.29.14', extnValue: new libraryASN1.Integer({ value: 1 }).toBER(),
    });
    assert.throws(() => helpers.parseExtensionValue(invalid, libraryASN1.OctetString, 'Invalid SKI'), /Invalid SKI/);

    const leaf = helpers.parsePemCertificate(pem);
    leaf.serialNumber = new asn1js.Integer({ value: 2 });
    leaf.extensions = [
        extension('2.5.29.35', new AuthorityKeyIdentifier({ keyIdentifier: new asn1js.OctetString({ valueHex: new Uint8Array([1, 2, 3, 4]) }) })),
        extension('2.5.29.31', new CRLDistributionPoints({ distributionPoints: [new DistributionPoint({
            distributionPoint: [new GeneralName({ type: 6, value: CRL_URL })],
        })] })),
    ];
    await leaf.sign(keys.privateKey, 'SHA-256');
    const signature = uint8ArrayToBase64(new Uint8Array(createCMSECDSASignature(await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, keys.privateKey, DATA))));
    const crl = new CertificateRevocationList({ version: 1, issuer: subject, thisUpdate: time('2000-01-01'), nextUpdate: time('2100-01-01') });
    t.mock.method(globalThis, 'fetch', async url => {
        assert.equal(url, CRL_URL);
        return new Response(crl.toSchema().toBER());
    });
    for(const variant of ['scripts/trusted-issuer-registry.js', 'build/trusted-issuer-registry.js', 'build/trusted-issuer-registry.min.js']) {
        const sdk = await import(pathToFileURL(path.join(library, variant)));
        assert.equal(await sdk.verifySignatureWithPem(pem, signature, DATA), true);
        assert.equal(await sdk.verifyCertificateSignature(leaf, issuer), true);
        for(const revoked of [false, true]) {
            crl.revokedCertificates = revoked ? [new RevokedCertificate({
                userCertificate: leaf.serialNumber, revocationDate: time('2000-01-01'),
                crlEntryExtensions: new Extensions({ extensions: [extension('2.5.29.21', new asn1js.Enumerated({ value: 1 }))] }),
            })] : [];
            await crl.sign(keys.privateKey, 'SHA-256');
            const registry = new sdk.Registry({ trustedIssuerCertificates: [pem], revocationCheckMode: sdk.RevocationCheckMode.REQUIRED });
            const result = await registry.resolveCertificateTrust(certificateToPem(leaf));
            assert.equal(result.trusted, !revoked);
            assert.equal(result.issuer.certificates[0].revocationStatus, revoked ? 'revoked' : 'not_revoked');
            if(revoked) assert.deepEqual(result.untrustedReasons, [sdk.UntrustedReason.CERTIFICATE_REVOKED]);
        }
    }
});

function time(date) {
    return new Time({ type: 1, value: new Date(date) });
}

function extension(extnID, value) {
    return new Extension({ extnID, extnValue: value.toSchema ? value.toSchema().toBER() : value.toBER() });
}
