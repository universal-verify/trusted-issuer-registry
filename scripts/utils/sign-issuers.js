import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import stringify from 'canonical-json';
import crypto from 'crypto';
import { PUBLIC_SIGNING_CERT } from '../constants.js';

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

// Function to validate private key PEM format
function validatePrivateKeyPem(privateKeyPem) {
    if (!privateKeyPem || typeof privateKeyPem !== 'string') {
        throw new Error('Private key PEM content must be provided as a string');
    }

    // Basic validation that it looks like an EC PEM private key
    if (!privateKeyPem.includes('-----BEGIN EC PRIVATE KEY-----') ||
        !privateKeyPem.includes('-----END EC PRIVATE KEY-----')) {
        throw new Error('Invalid private key PEM format. Expected to contain BEGIN and END EC PRIVATE KEY markers.');
    }

    return privateKeyPem;
}

// Function to sign data with private key
async function signData(privateKeyPem, data) {
    try {
        // Convert data to Buffer if it's a string
        const dataBuffer = typeof data === 'string' ? Buffer.from(data, 'utf8') : data;

        // Create sign object
        const sign = crypto.createSign('SHA256');
        sign.update(dataBuffer);
        sign.end();

        // Sign the data
        const signature = sign.sign(privateKeyPem, 'base64');

        return signature;
    } catch (error) {
        console.error('Error signing data:', error.message);
        throw error;
    }
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

// Function to process a single issuer file
async function processIssuerFile(filePath, privateKeyPem) {
    try {
        console.log(`Processing: ${filePath}`);

        // Read the JSON file
        const fileContent = fs.readFileSync(filePath, 'utf8');
        const issuer = JSON.parse(fileContent);

        // Check if it's an issuer file (has issuer_id)
        if (!issuer.issuer_id) {
            console.log(`Skipping ${filePath} - not an issuer file`);
            return;
        }

        // Create a copy without the signature
        const issuerCopy = { ...issuer };
        const existingSignature = issuerCopy.signature;
        delete issuerCopy.signature;

        // Create canonical JSON representation
        const canonicalJson = stringify(issuerCopy);

        // Check if signature already exists and is valid
        if (existingSignature) {
            const isExistingSignatureValid = verifySignature(PUBLIC_SIGNING_CERT, canonicalJson, existingSignature);
            if (isExistingSignatureValid) return;
        }

        // Sign the canonical JSON
        const signature = await signData(privateKeyPem, canonicalJson);

        // Verify the signature with the public key
        const isValid = verifySignature(PUBLIC_SIGNING_CERT, canonicalJson, signature);

        if (!isValid) {
            throw new Error('Signature verification failed - the created signature is invalid');
        }

        // Update the original issuer with the new signature
        issuer.signature = signature;

        // Write back to file
        fs.writeFileSync(filePath, JSON.stringify(issuer, null, 2) + '\n');

        console.log(`✓ Signed and verified: ${filePath}`);

    } catch (error) {
        console.error(`Error processing ${filePath}:`, error.message);
        throw error;
    }
}

// Main function
async function signIssuers(privateKeyPem) {
    try {
        // Validate the private key PEM content
        const validatedPrivateKeyPem = validatePrivateKeyPem(privateKeyPem);
        console.log('Private key validated successfully');

        const projectRoot = path.resolve(__dirname, '../..');

        // Define directories to process
        const directories = [
            path.join(projectRoot, 'issuers'),
            path.join(projectRoot, 'test', 'issuers')
        ];

        let totalFiles = 0;
        let processedFiles = 0;

        // Process each directory
        for (const dir of directories) {
            if (fs.existsSync(dir)) {
                console.log(`\nScanning directory: ${dir}`);
                const jsonFiles = findJsonFiles(dir);
                totalFiles += jsonFiles.length;

                for (const file of jsonFiles) {
                    await processIssuerFile(file, validatedPrivateKeyPem);
                    processedFiles++;
                }
            } else {
                console.log(`Directory not found: ${dir}`);
            }
        }

        console.log(`\nSigning complete! Processed ${processedFiles} of ${totalFiles} files.`);

    } catch (error) {
        console.error('Error during signing process:', error.message);
        process.exit(1);
    }
}

// Run the script if called directly
if (import.meta.url === `file://${process.argv[1]}`) {
    // Check if private key PEM content is provided as command line argument
    const privateKeyPem = process.argv[2];

    if (!privateKeyPem) {
        console.error('Usage: node sign-issuers.js <private-key-pem-content>');
        console.error('Please provide the private key PEM content as a command line argument.');
        process.exit(1);
    }

    signIssuers(privateKeyPem);
}

export { signIssuers };
