import { execSync } from 'child_process';

function hexToUrlSafeBase64(hexString) {
    // Remove colons and convert to byte array
    const hex = hexString.replace(/:/g, '');
    const bytes = new Uint8Array(hex.length / 2);

    for (let i = 0; i < hex.length; i += 2) {
        bytes[i / 2] = parseInt(hex.slice(i, i + 2), 16);
    }

    // Convert to standard Base64
    const base64 = Buffer.from(bytes).toString('base64');

    // Make it URL-safe
    return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function normalizePemContent(pemContent) {
    // Split the PEM content into lines
    const lines = pemContent.split('\n');

    // Find the start and end markers
    const startMarker = '-----BEGIN CERTIFICATE-----';
    const endMarker = '-----END CERTIFICATE-----';

    let startIndex = -1;
    let endIndex = -1;

    // Find the start and end marker indices
    for (let i = 0; i < lines.length; i++) {
        if (lines[i].includes(startMarker)) {
            startIndex = i;
        }
        if (lines[i].includes(endMarker)) {
            endIndex = i;
            break;
        }
    }

    if (startIndex === -1 || endIndex === -1) {
        throw new Error('Invalid PEM format: missing BEGIN or END markers');
    }

    // Extract the base64 content between markers
    const base64Lines = lines.slice(startIndex + 1, endIndex);
    const base64Content = base64Lines.join('').replace(/\s/g, ''); // Remove all whitespace

    // Split into 64-character lines (standard PEM line length)
    const normalizedLines = [];
    for (let i = 0; i < base64Content.length; i += 64) {
        normalizedLines.push(base64Content.slice(i, i + 64));
    }

    // Reconstruct the PEM with normalized lines
    const normalizedPem = [
        lines[startIndex], // BEGIN marker
        ...normalizedLines,
        lines[endIndex]    // END marker
    ].join('\n');

    return normalizedPem;
}

export default function extractCertificateInfo(pemContent) {
    try {
        // Use OpenSSL to extract certificate information from PEM content
        // Pipe the PEM content through stdin to openssl
        const opensslOutput = execSync('openssl x509 -noout -text', {
            input: pemContent,
            encoding: 'utf8'
        });

        // Find the Subject Key Identifier
        const skiMatch = opensslOutput.match(/X509v3 Subject Key Identifier:\s*\n\s*([A-F0-9:]+)/i);
        if (!skiMatch) {
            throw new Error('Subject Key Identifier not found in certificate');
        }
        const skiValue = skiMatch[1].trim();

        // Find the Subject information
        const subjectMatch = opensslOutput.match(/Subject: ([^\n]+)/);
        if (!subjectMatch) {
            throw new Error('Subject information not found in certificate');
        }

        // Parse subject components
        const subject = subjectMatch[1];
        const subjectParts = {};

        // Extract common fields from subject
        const cMatch = subject.match(/C\s*=\s*([^,\/]+)/);
        if (cMatch) subjectParts.country = cMatch[1];

        const stMatch = subject.match(/ST\s*=\s*([^,\/]+)/);
        if (stMatch) subjectParts.state = stMatch[1];

        const lMatch = subject.match(/L\s*=\s*([^,\/]+)/);
        if (lMatch) subjectParts.locality = lMatch[1];

        const oMatch = subject.match(/O\s*=\s*([^,\/]+)/);
        if (oMatch) subjectParts.organization = oMatch[1];

        const ouMatch = subject.match(/OU\s*=\s*([^,\/]+)/);
        if (ouMatch) subjectParts.organizationalUnit = ouMatch[1];

        const cnMatch = subject.match(/CN\s*=\s*([^,\/]+)/);
        if (cnMatch) subjectParts.commonName = cnMatch[1];

        // Check for CRL Distribution Points
        const crlMatch = opensslOutput.match(/X509v3 CRL Distribution Points:\s*\n((?:\s+[^\n]+\n?)*)/i);

        // Normalize certificate content to have standard width lines
        const certificateContent = normalizePemContent(pemContent);

        return {
            aki: hexToUrlSafeBase64(skiValue),
            subject: subjectParts,
            pemContent: certificateContent,
            crlMissing: crlMatch ? false : true
        };
    } catch (error) {
        throw new Error(`Failed to extract certificate information: ${error.message}`);
    }
}