import test from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import { generateKeyPairSync, verify } from 'node:crypto';
import { copyFileSync, mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import stringify from 'canonical-json';
import { buildRegistrySnapshot, validateRegistrySnapshot } from '../scripts/utils/registry-snapshot.js';

const ROOT = fileURLToPath(new URL('../', import.meta.url));

function fixture(t) {
    const root = mkdtempSync(path.join(process.env.TMPDIR || '/tmp', 'registry-snapshot-'));
    t.after(() => rmSync(root, { recursive: true, force: true }));
    mkdirSync(path.join(root, 'issuers/x509_aki/nested'), { recursive: true });
    writeFileSync(path.join(root, 'package.json'), JSON.stringify({ version: '0.2.3', type: 'module' }));
    writeFileSync(path.join(root, 'issuers/x509_aki/a.json'), JSON.stringify({
        issuer_id: 'x509_aki:a', certificates: [], signature: 'signature-a', display: { name: 'A' },
    }));
    writeFileSync(path.join(root, 'issuers/x509_aki/nested/b.json'), JSON.stringify({
        issuer_id: 'x509_aki:b', certificates: [{ data: 'PEM', format: 'pem', trust_lists: ['uv'] }], signature: 'signature-b', display: { name: 'B' },
    }));
    return root;
}

function signingFixture(t) {
    const root = fixture(t);
    mkdirSync(path.join(root, 'scripts/utils'), { recursive: true });
    mkdirSync(path.join(root, 'build'));
    for(const file of ['sign-issuers.js', 'registry-snapshot.js']) {
        copyFileSync(path.join(ROOT, 'scripts/utils', file), path.join(root, 'scripts/utils', file));
    }
    const { publicKey, privateKey } = generateKeyPairSync('ec', {
        namedCurve: 'prime256v1',
        publicKeyEncoding: { type: 'spki', format: 'pem' },
        privateKeyEncoding: { type: 'sec1', format: 'pem' },
    });
    writeFileSync(path.join(root, 'scripts/constants.js'), `export const PUBLIC_SIGNING_CERT = ${JSON.stringify(publicKey)};\n`);
    symlinkSync(path.join(ROOT, 'node_modules'), path.join(root, 'node_modules'), 'junction');
    const run = () => spawnSync(process.execPath, ['scripts/utils/sign-issuers.js', privateKey], { cwd: root, encoding: 'utf8' });
    return { root, publicKey, run };
}

test('manual signing refreshes the snapshot after signing and when signatures are already valid', t => {
    const { root, publicKey, run } = signingFixture(t);
    const bundle = path.join(root, 'build/trusted-issuer-registry.js');
    writeFileSync(bundle, 'Unchanged JavaScript bundle');
    const result = run();
    assert.equal(result.status, 0, result.stdout + result.stderr);
    assert.equal(validateRegistrySnapshot(root), 2);
    const filename = path.join(root, 'build/registry.json');
    const snapshot = readFileSync(filename, 'utf8');
    const issuers = JSON.parse(snapshot).issuers;
    for(const { signature, ...issuer } of issuers) {
        assert.equal(verify('SHA256', Buffer.from(stringify(issuer)), publicKey, Buffer.from(signature, 'base64')), true);
    }
    writeFileSync(filename, JSON.stringify({ version: 'stale', issuers: [] }));
    const repeated = run();
    assert.equal(repeated.status, 0, repeated.stdout + repeated.stderr);
    assert.equal(validateRegistrySnapshot(root), 2);
    assert.equal(readFileSync(filename, 'utf8'), snapshot);
    assert.equal(readFileSync(bundle, 'utf8'), 'Unchanged JavaScript bundle');
});

test('signing failures leave the previous snapshot unchanged', t => {
    const { root, run } = signingFixture(t);
    const filename = path.join(root, 'build/registry.json');
    const previous = JSON.stringify({ version: 'previous', issuers: [] });
    writeFileSync(filename, previous);
    writeFileSync(path.join(root, 'issuers/x509_aki/nested/b.json'), '{');
    const result = run();
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /Error during signing process/);
    assert.equal(readFileSync(filename, 'utf8'), previous);
});

test('snapshot generation includes all issuer files unchanged, including nested files and tombstones', t => {
    const root = fixture(t);
    const snapshot = buildRegistrySnapshot(root);
    assert.equal(snapshot.version, '0.2.3');
    assert.deepEqual(snapshot.issuers.map(issuer => issuer.issuer_id), ['x509_aki:a', 'x509_aki:b']);
    assert.equal(snapshot.issuers[0].certificates.length, 0);
    assert.equal(snapshot.issuers[1].signature, 'signature-b');
    assert.deepEqual(JSON.parse(readFileSync(path.join(root, 'build/registry.json'), 'utf8')), snapshot);
    assert.equal(validateRegistrySnapshot(root), 2);
    const firstBuild = readFileSync(path.join(root, 'build/registry.json'), 'utf8');
    buildRegistrySnapshot(root);
    assert.equal(readFileSync(path.join(root, 'build/registry.json'), 'utf8'), firstBuild);
});

test('snapshot validation rejects missing or malformed artifacts', t => {
    const root = fixture(t);
    assert.throws(() => validateRegistrySnapshot(root), /snapshot is missing/);
    buildRegistrySnapshot(root);
    writeFileSync(path.join(root, 'build/registry.json'), '{');
    assert.throws(() => validateRegistrySnapshot(root), SyntaxError);
});

test('snapshot validation rejects stale versions and missing, extra, duplicate or changed data', async t => {
    const root = fixture(t);
    const expected = buildRegistrySnapshot(root);
    const mutations = {
        'wrong version': snapshot => { snapshot.version = '0.2.2'; },
        'missing version': snapshot => { delete snapshot.version; },
        'missing issuers': snapshot => { delete snapshot.issuers; },
        'missing issuer': snapshot => { snapshot.issuers.pop(); },
        'extra issuer': snapshot => { snapshot.issuers.push({ ...snapshot.issuers[0], issuer_id: 'x509_aki:extra' }); },
        'duplicate issuer': snapshot => { snapshot.issuers[1] = snapshot.issuers[0]; },
        'changed metadata': snapshot => { snapshot.issuers[0].display.name = 'Changed'; },
        'changed certificate': snapshot => { snapshot.issuers[1].certificates[0].data = 'Different PEM'; },
        'changed trust lists': snapshot => { snapshot.issuers[1].certificates[0].trust_lists.push('aamva_dts'); },
        'changed signature': snapshot => { snapshot.issuers[0].signature = 'changed'; },
        'extra field': snapshot => { snapshot.issuers[0].extra = true; },
        'extra wrapper field': snapshot => { snapshot.extra = true; },
    };
    for(const [name, mutate] of Object.entries(mutations)) {
        await t.test(name, () => {
            const snapshot = structuredClone(expected);
            mutate(snapshot);
            writeFileSync(path.join(root, 'build/registry.json'), JSON.stringify(snapshot));
            assert.throws(() => validateRegistrySnapshot(root), /Registry snapshot/);
        });
    }
});

test('source changes and version bumps require rebuilding the snapshot', t => {
    const root = fixture(t);
    buildRegistrySnapshot(root);
    const filename = path.join(root, 'issuers/x509_aki/a.json');
    const issuer = JSON.parse(readFileSync(filename, 'utf8'));
    issuer.signature = 'new-signature';
    writeFileSync(filename, JSON.stringify(issuer));
    assert.throws(() => validateRegistrySnapshot(root), /does not match/);
    buildRegistrySnapshot(root);
    assert.equal(validateRegistrySnapshot(root), 2);
    writeFileSync(path.join(root, 'package.json'), JSON.stringify({ version: '0.2.4' }));
    assert.throws(() => validateRegistrySnapshot(root), /version must match/);
    buildRegistrySnapshot(root);
    assert.equal(validateRegistrySnapshot(root), 2);
});

test('snapshot generation rejects duplicate issuer identifiers in source files', t => {
    const root = fixture(t);
    copyFileSync(path.join(root, 'issuers/x509_aki/a.json'), path.join(root, 'issuers/x509_aki/c.json'));
    assert.throws(() => buildRegistrySnapshot(root), /duplicate issuer identifier/);
});

test('snapshot comparison ignores JSON whitespace and object property ordering', t => {
    const root = fixture(t);
    const snapshot = buildRegistrySnapshot(root);
    snapshot.issuers = snapshot.issuers.map(issuer => Object.fromEntries(Object.entries(issuer).reverse()));
    writeFileSync(path.join(root, 'build/registry.json'), JSON.stringify({ issuers: snapshot.issuers, version: snapshot.version }));
    assert.equal(validateRegistrySnapshot(root), 2);
});

test('the npm publish guard validates snapshots and deprecation notices', async t => {
    const root = fixture(t);
    rmSync(path.join(root, 'issuers/x509_aki'), { recursive: true });
    mkdirSync(path.join(root, 'issuers/x509_aki'));
    writeFileSync(path.join(root, 'package.json'), JSON.stringify({ version: '0.2.0', type: 'module' }));
    mkdirSync(path.join(root, 'scripts/utils'), { recursive: true });
    mkdirSync(path.join(root, '.github/workflows'), { recursive: true });
    for(const file of ['publish-sanity-checks.js', 'registry-snapshot.js', 'schema-check.js', 'signature-check.js']) {
        copyFileSync(path.join(ROOT, 'scripts/utils', file), path.join(root, 'scripts/utils', file));
    }
    copyFileSync(path.join(ROOT, 'scripts/constants.js'), path.join(root, 'scripts/constants.js'));
    copyFileSync(path.join(ROOT, 'trusted-issuer.schema.json'), path.join(root, 'trusted-issuer.schema.json'));
    copyFileSync(path.join(ROOT, '.github/workflows/sign_issuer_files.yml'), path.join(root, '.github/workflows/sign_issuer_files.yml'));
    symlinkSync(path.join(ROOT, 'node_modules'), path.join(root, 'node_modules'), 'junction');
    writeFileSync(path.join(root, '.gitignore'), 'node_modules\n');
    writeFileSync(path.join(root, 'mock-fetch.mjs'), `
        import assert from 'node:assert/strict';
        globalThis.fetch = async url => {
            assert.equal(url, 'https://cdn.jsdelivr.net/npm/trusted-issuer-registry@0.2.0/deprecation_notice.json');
            assert.notEqual(process.env.GUARD_PREVIOUS_STATUS, 'unexpected', 'Unexpected network request');
            return new Response(null, { status: Number(process.env.GUARD_PREVIOUS_STATUS) });
        };
    `);
    const git = args => execFileSync('git', ['-c', 'core.hooksPath=/dev/null', '-c', 'commit.gpgsign=false', '-c', 'user.name=Snapshot test', '-c', 'user.email=snapshot@example.test', ...args], { cwd: root, stdio: 'pipe' });
    git(['init', '-q', '-b', 'main']);
    buildRegistrySnapshot(root);
    git(['add', '.']);
    git(['commit', '-qm', 'Valid fixture']);
    const guard = (previousStatus = 'unexpected') => spawnSync(process.execPath, ['--import', './mock-fetch.mjs', 'scripts/utils/publish-sanity-checks.js'], {
        cwd: root, encoding: 'utf8', env: { ...process.env, GUARD_PREVIOUS_STATUS: String(previousStatus) },
    });
    const valid = guard();
    assert.equal(valid.status, 0, valid.stdout + valid.stderr);
    assert.match(valid.stdout, /Registry snapshot validation passed/);
    const snapshot = JSON.parse(readFileSync(path.join(root, 'build/registry.json'), 'utf8'));
    snapshot.version = '0.1.0';
    writeFileSync(path.join(root, 'build/registry.json'), JSON.stringify(snapshot));
    git(['add', '.']);
    git(['commit', '-qm', 'Stale fixture']);
    const stale = guard();
    assert.notEqual(stale.status, 0);
    assert.match(stale.stdout + stale.stderr, /Registry snapshot version must match/);
    assert.equal(JSON.parse(readFileSync(path.join(root, 'build/registry.json'), 'utf8')).version, '0.1.0');

    for(const [name, version, localNotice, previousStatus, error] of [
        ['new minor releases reject a deprecation notice', '0.2.0', true, 'unexpected', /Patch version is 0 but deprecation_notice\.json exists/],
        ['patch releases retain a local notice without requesting the CDN', '0.2.1', true, 'unexpected', null],
        ['patch releases cannot remove a previously published notice', '0.2.1', false, 200, /deprecation_notice\.json was removed/],
        ['patch releases allow a missing notice when the previous release has none', '0.2.1', false, 404, null],
    ]) {
        await t.test(name, () => {
            writeFileSync(path.join(root, 'package.json'), JSON.stringify({ version, type: 'module' }));
            const notice = path.join(root, 'deprecation_notice.json');
            if(localNotice) writeFileSync(notice, JSON.stringify({ version: '0.2', end_of_life: 1900000000 }));
            else rmSync(notice, { force: true });
            buildRegistrySnapshot(root);
            git(['add', '.']);
            git(['commit', '--allow-empty', '-qm', name]);
            const result = guard(previousStatus);
            if(error) {
                assert.notEqual(result.status, 0);
                assert.match(result.stdout + result.stderr, error);
            } else {
                assert.equal(result.status, 0, result.stdout + result.stderr);
                assert.match(result.stdout, /All pre-publish sanity checks passed/);
            }
        });
    }
});
