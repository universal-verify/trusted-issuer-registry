import test from 'node:test';
import assert from 'node:assert/strict';
import * as asn1js from 'asn1js';
import { AuthorityKeyIdentifier, Certificate, CRLDistributionPoints, Extension, ExtensionValueFactory } from 'pkijs';
import {
    certificateToPem,
    getAuthorityKeyIdentifier,
    getSubjectKeyIdentifier,
    parseExtensionValue,
    parsePemCertificate,
} from '../scripts/certificate-helper.js';
import { PUBLIC_SIGNING_CERT } from '../scripts/constants.js';

const IDENTIFIER = new Uint8Array([1, 2, 3, 4]);

test('PEM parsing delegates to PKIjs and preserves certificate serialization', t => {
    const fromBER = t.mock.method(Certificate, 'fromBER');
    const certificate = parsePemCertificate(`\n${PUBLIC_SIGNING_CERT.replace(/\n/g, '\r\n')}\n`);
    assert.ok(certificate instanceof Certificate);
    assert.equal(fromBER.mock.callCount(), 1);
    const pem = certificateToPem(certificate);
    assert.equal(certificateToPem(parsePemCertificate(pem)), pem);
});

test('PEM parsing rejects malformed ASN.1 and non-certificate structures', () => {
    assert.throws(() => parsePemCertificate(null), /PEM certificate must be a string/);
    for(const pem of ['', 'not a certificate', '-----BEGIN CERTIFICATE-----\nAgEB\n-----END CERTIFICATE-----']) {
        assert.throws(() => parsePemCertificate(pem));
    }
});

test('subject key identifiers reuse PKIjs cached extension decoding', t => {
    const decode = t.mock.method(ExtensionValueFactory, 'fromBER');
    const subjectKeyId = extension('2.5.29.14', new asn1js.OctetString({ valueHex: IDENTIFIER }));
    const certificate = new Certificate({ extensions: [subjectKeyId] });
    assert.equal(getSubjectKeyIdentifier(certificate), 'AQIDBA');
    assert.equal(getSubjectKeyIdentifier(certificate), 'AQIDBA');
    assert.ok(subjectKeyId.parsedValue instanceof asn1js.OctetString);
    assert.equal(decode.mock.callCount(), 1);
});

test('authority key identifiers reuse PKIjs cached extension decoding', t => {
    const decode = t.mock.method(ExtensionValueFactory, 'fromBER');
    const authorityKeyId = extension('2.5.29.35', new AuthorityKeyIdentifier({
        keyIdentifier: new asn1js.OctetString({ valueHex: IDENTIFIER }),
    }));
    const certificate = new Certificate({ extensions: [authorityKeyId] });
    assert.equal(getAuthorityKeyIdentifier(certificate), 'AQIDBA');
    assert.equal(getAuthorityKeyIdentifier(certificate), 'AQIDBA');
    assert.equal(decode.mock.callCount(), 1);
});

test('missing, empty and malformed key identifiers are not accepted', t => {
    t.mock.method(console, 'error', () => {});
    assert.equal(getSubjectKeyIdentifier(new Certificate()), null);
    assert.equal(getAuthorityKeyIdentifier(new Certificate()), null);
    for(const value of [new asn1js.OctetString(), new asn1js.Integer({ value: 1 })]) {
        assert.equal(getSubjectKeyIdentifier(new Certificate({ extensions: [extension('2.5.29.14', value)] })), null);
    }
    const invalid = new Extension({ extnID: '2.5.29.14', extnValue: new Uint8Array([0xff]) });
    assert.equal(getSubjectKeyIdentifier(new Certificate({ extensions: [invalid] })), null);
    const invalidAuthority = extension('2.5.29.35', new asn1js.Integer({ value: 1 }));
    assert.ok(invalidAuthority.parsedValue.parsingError);
    assert.equal(getAuthorityKeyIdentifier(new Certificate({ extensions: [invalidAuthority] })), null);
});

test('key usage and CRL reason values reuse PKIjs cached ASN.1 values', t => {
    const decode = t.mock.method(ExtensionValueFactory, 'fromBER');
    const keyUsage = extension('2.5.29.15', new asn1js.BitString({ valueHex: new Uint8Array([0x02]), unusedBits: 1 }));
    const reason = extension('2.5.29.21', new asn1js.Enumerated({ value: 8 }));
    assert.equal(parseExtensionValue(keyUsage, asn1js.BitString, 'Invalid key usage').valueBlock.valueHexView[0], 0x02);
    assert.equal(parseExtensionValue(reason, asn1js.Enumerated, 'Invalid CRL reason').valueBlock.valueDec, 8);
    assert.equal(parseExtensionValue(keyUsage, asn1js.BitString, 'Invalid key usage'), keyUsage.parsedValue);
    assert.equal(parseExtensionValue(reason, asn1js.Enumerated, 'Invalid CRL reason'), reason.parsedValue);
    assert.equal(decode.mock.callCount(), 2);
});

test('extension validation rejects wrong ASN.1 types and PKIjs parsing errors', () => {
    const wrongType = extension('2.5.29.21', new asn1js.Integer({ value: 8 }));
    assert.throws(() => parseExtensionValue(wrongType, asn1js.Enumerated, 'Invalid CRL reason'), /Invalid CRL reason/);
    const malformed = extension('2.5.29.31', new asn1js.Integer({ value: 1 }));
    assert.ok(malformed.parsedValue instanceof CRLDistributionPoints);
    assert.ok(malformed.parsedValue.parsingError);
    assert.throws(() => parseExtensionValue(malformed, CRLDistributionPoints, 'Invalid distribution points'), /Invalid distribution points/);
});

function extension(extnID, value) {
    return new Extension({ extnID, extnValue: value.toSchema ? value.toSchema().toBER() : value.toBER() });
}
