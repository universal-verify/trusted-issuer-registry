import { Buffer } from 'node:buffer';
import { verifySignatureWithPem } from 'trusted-issuer-registry';

export async function verifyNodeData(issuerPem: string, signature: string): Promise<boolean> {
    return verifySignatureWithPem(issuerPem, signature, Buffer.from('signed text'));
}
