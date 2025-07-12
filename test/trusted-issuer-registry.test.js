import test from 'node:test';
import assert from 'node:assert/strict';
import TrustedIssuerRegistry from '../scripts/trusted-issuer-registry.js';

const registry = new TrustedIssuerRegistry({ useTestData: true });

test('getIssuerFromX509AKI', async () => {
    const issuer = await registry.getIssuerFromX509AKI('q2Ub4FbCkFPx3X9s5Ie-aN5gyfU');
    assert.equal(issuer.issuer_id, 'x509_aki:q2Ub4FbCkFPx3X9s5Ie-aN5gyfU');
});