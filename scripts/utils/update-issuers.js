import fetchFromUV from './trust_lists/uv.js';
import fetchFromAAMVA from './trust_lists/aamva_dts.js';

/**
 * Main function that orchestrates fetching from different sources
 */
async function updateIssuers() {
    try {
        console.log('Starting issuer update process...');

        const allIssuers = {};
        // Fetch from Universal Verify
        await fetchFromUV(allIssuers);

        // Fetch from AAMVA (placeholder)
        await fetchFromAAMVA(allIssuers);

        console.log(`Total issuers collected from sources: ${Object.keys(allIssuers).length}`);

        // Process and update issuer files
        updateIssuerFiles(allIssuers);

        return allIssuers;

    } catch (error) {
        console.error('Error in updateIssuers:', error.message);
        throw error;
    }
}

import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

function updateIssuerFiles(issuers, options = {}) {
    const issuersDir = options.issuersDir || path.resolve(__dirname, '../..', 'issuers', 'x509_aki');
    let retiredCount = 0;
    let createdCount = 0;
    let updatedCount = 0;

    // Ensure the directory exists
    if (!fs.existsSync(issuersDir)) {
        fs.mkdirSync(issuersDir, { recursive: true });
    }

    // Get all existing files in the issuers/x509_aki directory
    const existingFiles = fs.readdirSync(issuersDir)
        .filter(file => file.endsWith('.json'))
        .map(file => file.replace('.json', ''));

    // Retain issuer files that no longer have corresponding trust-list data,
    // but remove their certificate entries. The reason we can't just delete the
    // issuer file is because requesting issuers from CDNs based on minor
    // version will resolve to the last patch version where the file existed,
    // which would cause people to get outdated trust-list information
    existingFiles.forEach(filename => {
        if (!issuers[filename]) {
            const filePath = path.join(issuersDir, `${filename}.json`);
            const existingData = JSON.parse(fs.readFileSync(filePath, 'utf8'));
            if (!Array.isArray(existingData.certificates) || existingData.certificates.length > 0) {
                existingData.certificates = [];
                fs.writeFileSync(filePath, JSON.stringify(existingData, null, 2));
                retiredCount++;
            }
        }
    });

    // Process each issuer
    Object.entries(issuers).forEach(([aki, issuerData]) => {
        const filePath = path.join(issuersDir, `${aki}.json`);
        const fileExists = fs.existsSync(filePath);

        if (fileExists) {
            // Check if the certificates array has changed
            const existingData = JSON.parse(fs.readFileSync(filePath, 'utf8'));
            const certificatesChanged = JSON.stringify(existingData.certificates) !== JSON.stringify(issuerData.certificates);

            if (certificatesChanged) {
                updatedCount++;
                // Update existing file - only update the certificates array
                existingData.certificates = issuerData.certificates;
                fs.writeFileSync(filePath, JSON.stringify(existingData, null, 2));
            }
        } else {
            // Create new file with complete issuer data
            fs.writeFileSync(filePath, JSON.stringify(issuerData, null, 2));
            createdCount++;
        }
    });

    if(retiredCount > 0) console.log(`Retired ${retiredCount} issuer files to certificate-less tombstones`);
    if(createdCount > 0) console.log(`Created ${createdCount} issuer files`);
    if(updatedCount > 0) console.log(`Updated ${updatedCount} issuer files`);
    if(!retiredCount && !createdCount && !updatedCount) console.log('No changes made to issuer files');

    return { retiredCount, createdCount, updatedCount };
}

// Run the script if called directly
if (import.meta.url === `file://${process.argv[1]}`) {
    updateIssuers()
        .catch(error => {
            console.error('Update process failed:', error.message);
            process.exit(1);
        });
}

export { updateIssuers, updateIssuerFiles };
