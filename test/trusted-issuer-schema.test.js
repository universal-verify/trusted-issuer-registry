import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import Ajv from 'ajv/dist/2020.js';
import addFormats from 'ajv-formats';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

function createValidator() {
    const schemaPath = path.resolve(__dirname, '..', 'trusted-issuer.schema.json');
    const schema = JSON.parse(fs.readFileSync(schemaPath, 'utf8'));
    const ajv = new Ajv({ allErrors: true, verbose: true });
    addFormats(ajv);
    return ajv.compile(schema);
}

function createIssuer(certificates, trustScopes = ['government_issued_id']) {
    return {
        issuer_id: 'x509_aki:tombstone',
        entity_type: 'government',
        entity_metadata: {
            country: 'US',
            region: 'CA'
        },
        display: {
            name: 'Example Issuer'
        },
        trust_scopes: trustScopes,
        certificates,
        signature: 'signature'
    };
}

test('trusted issuer schema accepts certificate-less issuer tombstones', () => {
    const validate = createValidator();
    const issuer = createIssuer([]);

    assert.equal(validate(issuer), true, JSON.stringify(validate.errors, null, 2));
});

test('trusted issuer schema accepts empty trust scopes', () => {
    const validate = createValidator();
    const issuer = createIssuer([], []);

    assert.equal(validate(issuer), true, JSON.stringify(validate.errors, null, 2));
});

test('trusted issuer schema rejects federated network entity type', () => {
    const validate = createValidator();
    const issuer = createIssuer([]);
    issuer.entity_type = 'federated_network';

    assert.equal(validate(issuer), false);
});

test('trusted issuer schema still accepts active issuer certificates', () => {
    const validate = createValidator();
    const issuer = createIssuer([
        {
            data: '-----BEGIN CERTIFICATE-----\nACTIVE\n-----END CERTIFICATE-----',
            format: 'pem',
            trust_lists: ['uv']
        }
    ]);

    assert.equal(validate(issuer), true, JSON.stringify(validate.errors, null, 2));
});
