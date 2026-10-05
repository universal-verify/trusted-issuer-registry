import test from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { cpSync, mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import ts from 'typescript';
import * as publicAPI from '../build/trusted-issuer-registry.js';

const ROOT = fileURLToPath(new URL('../', import.meta.url));
const TYPESCRIPT_CLI = path.join(ROOT, 'node_modules/typescript/bin/tsc');

test('declaration exports and constant values match the runtime API', () => {
    const source = readFileSync(path.join(ROOT, 'types/index.d.ts'), 'utf8');
    const declarations = ts.createSourceFile('index.d.ts', source, ts.ScriptTarget.Latest, true);
    const variables = declarations.statements.filter(ts.isVariableStatement)
        .flatMap(statement => [...statement.declarationList.declarations]);
    const declaredValues = [
        ...variables.map(declaration => declaration.name.getText()),
        ...declarations.statements.filter(statement => ts.isClassDeclaration(statement) || ts.isFunctionDeclaration(statement))
            .map(declaration => declaration.name.text),
    ];
    assert.deepEqual(declaredValues.sort(), Object.keys(publicAPI).sort());
    for(const name of ['TrustList', 'TrustScope', 'RevocationCheckMode', 'UntrustedReason']) {
        const declaration = variables.find(declaration => declaration.name.getText() === name);
        assert.ok(ts.isTypeLiteralNode(declaration.type));
        const values = Object.fromEntries(declaration.type.members.map(member => {
            assert.ok(ts.isLiteralTypeNode(member.type));
            assert.ok(ts.isStringLiteral(member.type.literal));
            return [member.name.getText(), member.type.literal.text];
        }));
        assert.deepEqual(values, publicAPI[name]);
    }
});

test('published declarations support strict NodeNext and browser/bundler consumers', async t => {
    const directory = mkdtempSync(path.join(tmpdir(), 'trusted-issuer-types-'));
    t.after(() => rmSync(directory, { recursive: true, force: true }));

    const [packed] = JSON.parse(execFileSync('npm', [
        'pack', '--json', '--ignore-scripts', '--pack-destination', directory,
        '--cache', path.join(directory, 'npm-cache'),
    ], { cwd: ROOT, encoding: 'utf8' }));
    const shippedFiles = new Set(packed.files.map(file => file.path));
    assert.ok(shippedFiles.has('types/index.d.ts'));
    for(const variant of ['', '.min', '.bundled', '.bundled.min']) {
        assert.ok(shippedFiles.has(`build/trusted-issuer-registry${variant}.d.ts`));
        assert.ok(shippedFiles.has(`build/trusted-issuer-registry${variant}.js`));
    }

    execFileSync('tar', ['-xzf', path.join(directory, packed.filename), '-C', directory]);
    const packageDirectory = path.join(directory, 'package');
    const metadata = JSON.parse(readFileSync(path.join(packageDirectory, 'package.json'), 'utf8'));
    assert.equal(metadata.type, 'module');
    assert.equal(metadata.main, 'build/trusted-issuer-registry.js');
    assert.equal(metadata.types, 'types/index.d.ts');

    cpSync(new URL('../types/fixtures/', import.meta.url), directory, { recursive: true });
    writeFileSync(path.join(directory, 'package.json'), JSON.stringify({ private: true, type: 'module' }));
    const nodeModules = path.join(directory, 'node_modules');
    mkdirSync(nodeModules);
    symlinkSync(packageDirectory, path.join(nodeModules, 'trusted-issuer-registry'), 'junction');
    for(const dependency of ['pkijs', '@types']) {
        symlinkSync(path.join(ROOT, 'node_modules', dependency), path.join(nodeModules, dependency), 'junction');
    }

    for(const configuration of ['node', 'browser']) {
        await t.test(configuration, () => {
            execFileSync(process.execPath, [TYPESCRIPT_CLI, '--project', `tsconfig.${configuration}.json`], {
                cwd: directory,
                stdio: 'pipe',
            });
        });
    }
});
