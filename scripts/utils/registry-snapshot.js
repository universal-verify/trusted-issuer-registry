import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { isDeepStrictEqual } from 'util';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const PROJECT_ROOT = path.resolve(__dirname, '../..');

function readIssuers(directory) {
    const issuers = [];
    const items = fs.readdirSync(directory).sort();

    for (const name of items) {
        const filename = path.join(directory, name);
        if (fs.statSync(filename).isDirectory()) {
            issuers.push(...readIssuers(filename));
        } else if (name.endsWith('.json')) {
            issuers.push(JSON.parse(fs.readFileSync(filename, 'utf8')));
        }
    }

    return issuers;
}

function createRegistrySnapshot(root) {
    const { version } = JSON.parse(fs.readFileSync(path.join(root, 'package.json'), 'utf8'));
    const issuers = readIssuers(path.join(root, 'issuers'));
    const identifiers = new Set();
    for (const issuer of issuers) {
        if (typeof issuer.issuer_id !== 'string' || identifiers.has(issuer.issuer_id)) {
            throw new Error(`Missing or duplicate issuer identifier: ${issuer.issuer_id}`);
        }
        identifiers.add(issuer.issuer_id);
    }
    return { version, issuers };
}

function buildRegistrySnapshot(root = PROJECT_ROOT) {
    const snapshot = createRegistrySnapshot(root);
    const directory = path.join(root, 'build');
    fs.mkdirSync(directory, { recursive: true });
    fs.writeFileSync(path.join(directory, 'registry.json'), `${JSON.stringify(snapshot, null, 2)}\n`);
    return snapshot;
}

function validateRegistrySnapshot(root = PROJECT_ROOT) {
    const expected = createRegistrySnapshot(root);
    const filename = path.join(root, 'build', 'registry.json');
    if (!fs.existsSync(filename)) {
        throw new Error('Registry snapshot is missing; run npm run build');
    }
    const snapshot = JSON.parse(fs.readFileSync(filename, 'utf8'));
    if (snapshot?.version !== expected.version) {
        throw new Error(`Registry snapshot version must match package.json (${expected.version}); run npm run build`);
    }
    if (!isDeepStrictEqual(snapshot, expected)) {
        throw new Error('Registry snapshot does not match the issuer files; run npm run build');
    }
    return snapshot.issuers.length;
}

if (__filename === process.argv[1]) {
    const snapshot = buildRegistrySnapshot();
    console.log(`Built registry snapshot ${snapshot.version} with ${snapshot.issuers.length} issuers`);
}

export { buildRegistrySnapshot, validateRegistrySnapshot };
