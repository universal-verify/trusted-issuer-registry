import { verifySignatureWithPem } from 'trusted-issuer-registry';

export async function verifyBrowserData(issuerPem: string, signature: string): Promise<boolean> {
    const data = new TextEncoder().encode('signed text');
    return verifySignatureWithPem(issuerPem, signature, data);
}
