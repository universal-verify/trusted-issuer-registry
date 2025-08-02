import getCertInfo from '../extract-pem-info.js';
import * as cbor2 from 'cbor2';

/**
 * Fetches issuer data from Universal Verify trust list
 * @returns {Promise<Object>} Object with AKI as keys and certificate info as values
 */
export default async function fetchFromAAMVA(obj = {}) {
    try {
        console.log('Fetching issuer data from AAMVA DTS trust list...');

        const response = await fetch('https://vical.dts.aamva.org/vical/vc');
        if (!response.ok) throw new Error(`Failed to fetch AAMVA DTS VICAL: ${response.status} ${response.statusText}`);

        const cbor = await response.arrayBuffer();
        if (!cbor) throw new Error('AAMVA DTS VICAL is empty');
        const uint8Array = new Uint8Array(cbor);
        const decoded = cbor2.decode(uint8Array);

        const [_protectedHeader, _unprotectedHeader, payload, _signature] = decoded;

        //console.log('protectedHeader', _protectedHeader);
        //console.log('unprotectedHeader', _unprotectedHeader);
        //console.log('payload', payload);
        //console.log('signature', _signature);

        const payloadDecoded = cbor2.decode(payload);
        //console.log('payloadDecoded', payloadDecoded);

        let count = 0;
        let missingCRLCount = 0;

        for(const certificateInfo of payloadDecoded.certificateInfos) {
            const certContent = Buffer.from(certificateInfo.certificate).toString('base64').match(/.{1,64}/g).join('\n');
            const certInfo = getCertInfo(`-----BEGIN CERTIFICATE-----\n${certContent}\n-----END CERTIFICATE-----`);
            //console.log('certInfo', certInfo);
            if(certInfo.crlMissing) {
                missingCRLCount++;
            } else {
                addCert(obj, certInfo);
                count++;
            }
        }

        if(missingCRLCount > 0) console.warn(`${missingCRLCount} certificate(s) have missing CRLs`);
        console.log(`Successfully ingested ${count} certificate(s) from AAMVA DTS trust list`);
        return obj;
    } catch (error) {
        console.error('Error fetching from AAMVA DTS:', error.message);
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
                'trust_lists': ['aamva_dts']
            }]
        };
    } else {
        for(const cert of obj[certInfo.aki].certificates) {
            if(cert.data === certInfo.pemContent) {
                if(!cert.trust_lists.includes('aamva_dts')) {
                    cert.trust_lists.push('aamva_dts');
                }
                return;
            }
        }
        obj[certInfo.aki].certificates.push({
            'data': certInfo.pemContent,
            'format': 'pem',
            'trust_lists': ['aamva_dts']
        });
    }
}

// Run the script if called directly
if (import.meta.url === `file://${process.argv[1]}`) {
    fetchFromAAMVA()
        .then(obj => {
            console.log(obj);
        })
        .catch(error => {
            console.error('Update process failed:', error.message);
            process.exit(1);
        });
}