import { execFileSync } from 'child_process';
import fs from 'fs';
import path from 'path';

function printUsage() {
    console.log(`Usage: npm run decode-certificate -- <issuer-file> [--index <number>]

Reads a trusted issuer JSON file, extracts its PEM certificate data, and prints
the decoded X.509 certificate information.

Examples:
  npm run decode-certificate -- issuers/x509_aki/TprRzaFBJ1SLjJsO01tlLCQ4YF0.json
  npm run decode-certificate -- issuers/x509_aki/TprRzaFBJ1SLjJsO01tlLCQ4YF0.json --index 1`);
}

function parseArgs(argv) {
    const args = [...argv];

    if (args.includes('--help') || args.includes('-h')) {
        return { help: true };
    }

    const issuerFile = args.shift();
    let certificateIndex;

    while (args.length > 0) {
        const arg = args.shift();

        if (arg === '--index') {
            const rawIndex = args.shift();
            certificateIndex = parseCertificateIndex(rawIndex);
        } else {
            throw new Error(`Unknown argument: ${arg}`);
        }
    }

    if (!issuerFile) {
        throw new Error('Missing issuer file path');
    }

    return { issuerFile, certificateIndex };
}

function parseCertificateIndex(rawIndex) {
    if (!rawIndex) {
        throw new Error('Missing value for --index');
    }

    const index = Number.parseInt(rawIndex, 10);

    if (!Number.isInteger(index) || index < 1 || index.toString() !== rawIndex) {
        throw new Error('--index must be a positive integer, starting at 1');
    }

    return index - 1;
}

function readIssuerFile(issuerFile) {
    const issuerPath = path.resolve(process.cwd(), issuerFile);

    if (!fs.existsSync(issuerPath)) {
        throw new Error(`Issuer file not found: ${issuerFile}`);
    }

    const issuer = JSON.parse(fs.readFileSync(issuerPath, 'utf8'));

    if (!Array.isArray(issuer.certificates) || issuer.certificates.length === 0) {
        throw new Error('Issuer file does not contain any certificates');
    }

    return { issuer, issuerPath };
}

function getCertificatesToDecode(certificates, certificateIndex) {
    if (certificateIndex === undefined) {
        return certificates.map((certificate, index) => ({ certificate, index }));
    }

    const certificate = certificates[certificateIndex];

    if (!certificate) {
        throw new Error(`Certificate index ${certificateIndex + 1} is out of range`);
    }

    return [{ certificate, index: certificateIndex }];
}

function decodeCertificate(certificate) {
    if (certificate.format !== 'pem') {
        throw new Error(`Unsupported certificate format: ${certificate.format}`);
    }

    if (typeof certificate.data !== 'string' || !certificate.data.trim()) {
        throw new Error('Certificate data is empty or missing');
    }

    try {
        return execFileSync('openssl', ['x509', '-noout', '-text', '-fingerprint', '-sha256'], {
            input: certificate.data,
            encoding: 'utf8',
            stdio: ['pipe', 'pipe', 'pipe']
        });
    } catch (error) {
        if (error.code === 'ENOENT') {
            throw new Error('OpenSSL is required to decode certificates, but the openssl command was not found');
        }

        const stderr = error.stderr ? error.stderr.toString().trim() : '';
        throw new Error(`OpenSSL failed to decode certificate${stderr ? `: ${stderr}` : ''}`);
    }
}

function printIssuerSummary(issuer, issuerPath) {
    const relativePath = path.relative(process.cwd(), issuerPath);
    const displayName = issuer.display && issuer.display.name ? issuer.display.name : 'Unknown';

    console.log(`Issuer file: ${relativePath}`);
    console.log(`Issuer ID: ${issuer.issuer_id || 'Unknown'}`);
    console.log(`Display name: ${displayName}`);
    console.log(`Entity type: ${issuer.entity_type || 'Unknown'}`);
    console.log(`Certificates: ${issuer.certificates.length}`);
}

function printCertificateInfo(certificate, index, total) {
    console.log(`\nCertificate ${index + 1} of ${total}`);
    console.log(`Format: ${certificate.format || 'Unknown'}`);
    console.log(`Trust lists: ${Array.isArray(certificate.trust_lists) ? certificate.trust_lists.join(', ') : 'None'}`);
    console.log('');
    console.log(decodeCertificate(certificate).trimEnd());
}

export function decodeIssuerCertificates(issuerFile, options = {}) {
    const { issuer, issuerPath } = readIssuerFile(issuerFile);
    const certificates = getCertificatesToDecode(issuer.certificates, options.certificateIndex);

    printIssuerSummary(issuer, issuerPath);

    for (const { certificate, index } of certificates) {
        printCertificateInfo(certificate, index, issuer.certificates.length);
    }
}

if (import.meta.url === `file://${process.argv[1]}`) {
    try {
        const args = parseArgs(process.argv.slice(2));

        if (args.help) {
            printUsage();
            process.exit(0);
        }

        decodeIssuerCertificates(args.issuerFile, { certificateIndex: args.certificateIndex });
    } catch (error) {
        console.error(`Error: ${error.message}`);
        console.error('');
        printUsage();
        process.exit(1);
    }
}
