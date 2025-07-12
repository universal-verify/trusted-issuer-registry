import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import stringify from 'canonical-json';
import crypto from 'crypto';

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

// Function to read and parse private key
function loadPrivateKey(keyPath) {
    try {
        const keyPem = fs.readFileSync(keyPath, 'utf8');
        return keyPem;
    } catch (error) {
        console.error(`Error loading private key from ${keyPath}:`, error.message);
        throw error;
    }
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
        delete issuerCopy.signature;

        // Create canonical JSON representation
        const canonicalJson = stringify(issuerCopy);

        // Sign the canonical JSON
        const signature = await signData(privateKeyPem, canonicalJson);

        // Update the original issuer with the new signature
        issuer.signature = signature;

        // Write back to file
        fs.writeFileSync(filePath, JSON.stringify(issuer, null, 2) + '\n');

        console.log(`✓ Signed: ${filePath}`);

    } catch (error) {
        console.error(`Error processing ${filePath}:`, error.message);
    }
}

// Main function
async function signIssuers() {
    try {
        const projectRoot = path.resolve(__dirname, '..');
        const privateKeyPath = path.join(projectRoot, 'keys', 'uv_private.pem');

        // Check if private key exists
        if (!fs.existsSync(privateKeyPath)) {
            console.error(`Private key not found at: ${privateKeyPath}`);
            console.error('Please create the private key file first.');
            process.exit(1);
        }

        // Load private key
        const privateKeyPem = loadPrivateKey(privateKeyPath);
        console.log('Private key loaded successfully');

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
                    await processIssuerFile(file, privateKeyPem);
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
    signIssuers();
}

export { signIssuers };