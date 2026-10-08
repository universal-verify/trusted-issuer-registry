import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

test('CBOR import tooling is a pinned development-only dependency', () => {
    const metadata = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8'));
    const lockfile = JSON.parse(readFileSync(new URL('../package-lock.json', import.meta.url), 'utf8'));
    assert.equal(metadata.dependencies.cbor2, undefined);
    assert.equal(metadata.devDependencies.cbor2, '2.3.0');
    assert.equal(lockfile.packages[''].dependencies.cbor2, undefined);
    assert.equal(lockfile.packages[''].devDependencies.cbor2, '2.3.0');
    assert.equal(lockfile.packages['node_modules/cbor2'].dev, true);
});
