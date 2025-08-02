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
        const cMatch = subject.match(/C=([^,\/]+)/);
        if (cMatch) subjectParts.country = cMatch[1];

        const stMatch = subject.match(/ST=([^,\/]+)/);
        if (stMatch) subjectParts.state = stMatch[1];

        const lMatch = subject.match(/L=([^,\/]+)/);
        if (lMatch) subjectParts.locality = lMatch[1];

        const oMatch = subject.match(/O=([^,\/]+)/);
        if (oMatch) subjectParts.organization = oMatch[1];

        const ouMatch = subject.match(/OU=([^,\/]+)/);
        if (ouMatch) subjectParts.organizationalUnit = ouMatch[1];

        const cnMatch = subject.match(/CN=([^,\/]+)/);
        if (cnMatch) subjectParts.commonName = cnMatch[1];

        // Check for CRL Distribution Points
        const crlMatch = opensslOutput.match(/X509v3 CRL Distribution Points:\s*\n((?:\s+[^\n]+\n?)*)/i);

        // Use the provided PEM content directly
        const certificateContent = pemContent;

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