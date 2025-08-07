import getCertInfo from '../extract-pem-info.js';

/**
 * Fetches issuer data from Universal Verify trust list
 * @returns {Promise<Object>} Object with AKI as keys and certificate info as values
 */
export default async function fetchFromUV(obj = {}) {
    try {
        console.log('Fetching issuer data from Universal Verify trust list...');

        const response = await fetch('https://cdn.jsdelivr.net/npm/@universal-verify/trust-list@0.1/trust-list.json');

        if (!response.ok) throw new Error(`Failed to fetch trust list: ${response.status} ${response.statusText}`);

        const trustList = await response.json();

        if (!Array.isArray(trustList)) throw new Error('Trust list is not an array');

        let count = 0;
        let missingCRLCount = 0;

        for (const issuer of trustList) {
            // Extract AKI from issuer_id (format: "x509_aki:AKI_VALUE")
            const akiMatch = issuer.issuer_id?.match(/^x509_aki:(.+)$/);
            if (!akiMatch) {
                console.warn(`Skipping issuer with invalid issuer_id format: ${issuer.issuer_id}`);
                continue;
            }

            if (issuer.certificates && issuer.certificates.length > 0) {
                for(const cert of issuer.certificates) {
                    const certInfo = getCertInfo(cert.data);
                    if(certInfo.crlMissing) {
                        missingCRLCount++;
                    } else {
                        addCert(obj, certInfo);
                        count++;
                    }
                }
            } else {
                console.warn(`Skipping issuer ${issuer.issuer_id} - no certificates array`);
            }
        }

        if(missingCRLCount > 0) console.warn(`${missingCRLCount} certificate(s) have missing CRLs`);
        console.log(`Successfully ingested ${count} certificate(s) from UV trust list`);
        return obj;
    } catch (error) {
        console.error('Error fetching from Universal Verify:', error.message);
        throw error;
    }
}

function addCert(obj, certInfo) {
    const region = (certInfo.subject.state) ? certInfo.subject.state.replace('US-', '') : '';

    if(!obj[certInfo.aki]) {
        obj[certInfo.aki] = {
            'issuer_id': `x509_aki:${certInfo.aki}`,
            'entity_type': 'government',
            'entity_metadata': {
                'country': certInfo.subject.country || '',
                'region': (region) ? region : undefined,
                'government_level': (region) ? 'state' : 'national',
                'official_name': certInfo.subject.organization || certInfo.subject.commonName || ''
            },
            'display': {
                'name': certInfo.subject.organization || certInfo.subject.commonName || '',
            },
            'certificates': [{
                'data': certInfo.pemContent,
                'format': 'pem',
                'trust_lists': ['uv']
            }]
        };
    } else {
        for(const cert of obj[certInfo.aki].certificates) {
            if(cert.data === certInfo.pemContent) {
                if(!cert.trust_lists.includes('uv')) {
                    cert.trust_lists.push('uv');
                }
                return;
            }
        }
        obj[certInfo.aki].certificates.push({
            'data': certInfo.pemContent,
            'format': 'pem',
            'trust_lists': ['uv']
        });
    }
}

// Run the script if called directly
if (import.meta.url === `file://${process.argv[1]}`) {
    fetchFromUV()
        .then(obj => {
            console.log(obj);
        })
        .catch(error => {
            console.error('Update process failed:', error.message);
            process.exit(1);
        });
}
