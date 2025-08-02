import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import stringify from 'canonical-json';
import crypto from 'crypto';
import { PUBLIC_SIGNING_KEY } from '../constants.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Function to recursively find all JSON files in a directory
function findJsonFiles(dir) {
    const files = [];

    function traverse(currentDir) {
        const items = fs.readdirSync(currentDir);

        for (const item of items) {
            const fullPath = path.join(currentDir, item);
            const stat = fs.statSync(fullPath);

            if (stat.isDirectory()) {
                traverse(fullPath);
            } else if (item.endsWith('.json')) {
                files.push(fullPath);
            }
        }
    }

    traverse(dir);
    return files;
}

// Function to verify signature with public key
function verifySignature(publicKeyPem, data, signature) {
    try {
        // Convert data to Buffer if it's a string
        const dataBuffer = typeof data === 'string' ? Buffer.from(data, 'utf8') : data;

        // Create verify object
        const verify = crypto.createVerify('SHA256');
        verify.update(dataBuffer);
        verify.end();

        // Verify the signature
        const isValid = verify.verify(publicKeyPem, signature, 'base64');

        return isValid;
    } catch (error) {
        console.error('Error verifying signature:', error.message);
        return false;
    }
}

// Function to validate signature for a single issuer file
function validateIssuerSignature(filePath) {
    try {
        // Read the JSON file
        const fileContent = fs.readFileSync(filePath, 'utf8');
        const issuer = JSON.parse(fileContent);

        // Check if it's an issuer file (has issuer_id)
        if (!issuer.issuer_id) {
            return { valid: true, reason: 'Not an issuer file' };
        }

        // Check if it has a signature
        if (!issuer.signature) {
            return { valid: false, reason: 'Missing signature' };
        }

        // Create a copy without the signature for verification
        const issuerCopy = { ...issuer };
        delete issuerCopy.signature;

        // Create canonical JSON representation
        const canonicalJson = stringify(issuerCopy);

        // Verify the signature
        const isValid = verifySignature(PUBLIC_SIGNING_KEY, canonicalJson, issuer.signature);

        if (!isValid) {
            return { valid: false, reason: 'Invalid signature' };
        }

        return { valid: true, reason: 'Valid signature' };

    } catch (error) {
        return { valid: false, reason: `Error processing file: ${error.message}` };
    }
}

// Main function to validate all issuer signatures
function validateSignatureFiles() {
    const projectRoot = path.resolve(__dirname, '../..');

    // Define directories to check
    const directories = [
        path.join(projectRoot, 'issuers'),
        path.join(projectRoot, 'test', 'issuers')
    ];

    let validFiles = 0;
    const invalidFiles = [];

    // Process each directory
    for (const dir of directories) {
        if (fs.existsSync(dir)) {
            const jsonFiles = findJsonFiles(dir);

            for (const file of jsonFiles) {
                const result = validateIssuerSignature(file);
                if (result.valid) {
                    validFiles++;
                } else {
                    invalidFiles.push({ file, reason: result.reason });
                }
            }
        }
    }

    // Report any invalid files
    if (invalidFiles.length > 0) {
        console.error('❌ Signature validation failed for the following files:');
        for (const { file, reason } of invalidFiles) {
            console.error(`   ${file}: ${reason}`);
        }
        throw new Error(`${invalidFiles.length} files have invalid signatures`);
    }

    return validFiles;
}

// Run the script if called directly
if (import.meta.url === `file://${process.argv[1]}`) {
    const validFiles = validateSignatureFiles();
    console.log(`✅ Signature validation passed: ${validFiles} valid files checked.`);
}

export { validateSignatureFiles };