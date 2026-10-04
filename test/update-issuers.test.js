import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { updateIssuerFiles } from '../scripts/utils/update-issuers.js';

const CERTIFICATE = {
    data: '-----BEGIN CERTIFICATE-----\nACTIVE\n-----END CERTIFICATE-----',
    format: 'pem',
    trust_lists: ['uv']
};

function createIssuer(aki, certificates = [CERTIFICATE]) {
    return {
        issuer_id: `x509_aki:${aki}`,
        entity_type: 'government',
        entity_metadata: {
            country: 'US',
            region: 'CA'
        },
        display: {
            name: 'Example Issuer'
        },
        trust_scopes: ['government_issued_id'],
        certificates,
        signature: 'signature'
    };
}

function createTempIssuersDir(t) {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'trusted-issuer-registry-'));
    const issuersDir = path.join(root, 'issuers', 'x509_aki');
    fs.mkdirSync(issuersDir, { recursive: true });
    t.after(() => fs.rmSync(root, { recursive: true, force: true }));
    return issuersDir;
}

function issuerPath(issuersDir, aki) {
    return path.join(issuersDir, `${aki}.json`);
}

function writeIssuer(issuersDir, issuer) {
    fs.writeFileSync(issuerPath(issuersDir, issuer.issuer_id.replace('x509_aki:', '')), JSON.stringify(issuer, null, 2));
}

function readIssuer(issuersDir, aki) {
    return JSON.parse(fs.readFileSync(issuerPath(issuersDir, aki), 'utf8'));
}

test('updateIssuerFiles keeps missing issuers as certificate-less tombstones', t => {
    const issuersDir = createTempIssuersDir(t);
    const aki = 'retired';

    writeIssuer(issuersDir, createIssuer(aki));

    const counts = updateIssuerFiles({}, { issuersDir });

    assert.deepEqual(counts, { retiredCount: 1, createdCount: 0, updatedCount: 0 });
    assert.equal(fs.existsSync(issuerPath(issuersDir, aki)), true);
    assert.deepEqual(readIssuer(issuersDir, aki).certificates, []);
});

test('updateIssuerFiles leaves active issuers with fetched certificates', t => {
    const issuersDir = createTempIssuersDir(t);
    const aki = 'active';
    const issuer = createIssuer(aki);

    const counts = updateIssuerFiles({ [aki]: issuer }, { issuersDir });

    assert.deepEqual(counts, { retiredCount: 0, createdCount: 1, updatedCount: 0 });
    assert.deepEqual(readIssuer(issuersDir, aki).certificates, [CERTIFICATE]);
});

test('updateIssuerFiles repopulates certificates for reactivated issuers', t => {
    const issuersDir = createTempIssuersDir(t);
    const aki = 'reactivated';
    const reactivatedCertificate = {
        data: '-----BEGIN CERTIFICATE-----\nREACTIVATED\n-----END CERTIFICATE-----',
        format: 'pem',
        trust_lists: ['aamva_dts']
    };

    writeIssuer(issuersDir, createIssuer(aki, []));

    const counts = updateIssuerFiles({ [aki]: createIssuer(aki, [reactivatedCertificate]) }, { issuersDir });

    assert.deepEqual(counts, { retiredCount: 0, createdCount: 0, updatedCount: 1 });
    assert.deepEqual(readIssuer(issuersDir, aki).certificates, [reactivatedCertificate]);
});

test('updateIssuerFiles preserves existing issuer metadata when certificates change', t => {
    const issuersDir = createTempIssuersDir(t);
    const aki = 'curated';
    const updatedCertificate = {
        data: '-----BEGIN CERTIFICATE-----\nUPDATED\n-----END CERTIFICATE-----',
        format: 'pem',
        trust_lists: ['uv']
    };
    const existingIssuer = createIssuer(aki);
    existingIssuer.entity_type = 'commercial';
    existingIssuer.entity_metadata = {
        country: 'US',
        region: 'NY'
    };
    existingIssuer.display = {
        name: 'Curated Display Name'
    };
    existingIssuer.trust_scopes = ['document_signing'];

    writeIssuer(issuersDir, existingIssuer);

    const counts = updateIssuerFiles({ [aki]: createIssuer(aki, [updatedCertificate]) }, { issuersDir });
    const updatedIssuer = readIssuer(issuersDir, aki);

    assert.deepEqual(counts, { retiredCount: 0, createdCount: 0, updatedCount: 1 });
    assert.equal(updatedIssuer.entity_type, 'commercial');
    assert.deepEqual(updatedIssuer.entity_metadata, existingIssuer.entity_metadata);
    assert.deepEqual(updatedIssuer.display, existingIssuer.display);
    assert.deepEqual(updatedIssuer.trust_scopes, existingIssuer.trust_scopes);
    assert.deepEqual(updatedIssuer.certificates, [updatedCertificate]);
});
