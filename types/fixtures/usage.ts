import {
    Registry,
    RevocationCheckMode,
    TrustList,
    TrustScope,
    UntrustedReason,
    certificateToPem,
    parsePemCertificate,
    verifyCertificateSignature,
    verifySignatureWithPem,
} from 'trusted-issuer-registry';
import type {
    CertificateInput,
    CertificateTrustResult,
    EntityMetadata,
    EntityType,
    Issuer,
    IssuerCertificate,
    IssuerDisplay,
    RegistryOptions,
    ResolveCertificateTrustOptions,
    ResolvedIssuer,
    ResolvedIssuerCertificate,
    RevocationStatus,
    UserTrustedIssuerCertificate,
} from 'trusted-issuer-registry';
import { Certificate } from 'pkijs';
import { Registry as UnbundledRegistry } from 'trusted-issuer-registry/build/trusted-issuer-registry.js';
import { Registry as MinifiedRegistry } from 'trusted-issuer-registry/build/trusted-issuer-registry.min.js';
import { Registry as BundledRegistry } from 'trusted-issuer-registry/build/trusted-issuer-registry.bundled.js';
import { Registry as BundledMinifiedRegistry } from 'trusted-issuer-registry/build/trusted-issuer-registry.bundled.min.js';

function expectType<T>(value: T): void {
    void value;
}

export async function exerciseOptionalInputs(
    certificatePem: string,
    issuerPem: string,
    trustScope: TrustScope | undefined,
    timeout: number | undefined,
): Promise<void> {
    const registry = new Registry({
        trustedIssuerCertificates: undefined,
        revocationCheckMode: undefined,
        timeout,
        cacheEnabled: undefined,
        cacheTTL: undefined,
    });
    new Registry(undefined);
    new Registry({ trustedIssuerCertificates: [
        {
            data: issuerPem,
            format: undefined,
            trust_scopes: undefined,
            entity_type: undefined,
            entity_metadata: undefined,
            display: undefined,
        },
        {
            data: issuerPem,
            entity_metadata: { country: undefined, region: undefined },
            display: { name: undefined, logo: undefined, description: undefined },
        },
    ] });
    await registry.resolveCertificateTrust(certificatePem, { trustLists: undefined, trustScope });
    await registry.resolveCertificateTrust(certificatePem, undefined);
}

export async function exerciseAPI(certificatePem: string, issuerPem: string, signature: string): Promise<void> {
    expectType<'uv'>(TrustList.UV);
    expectType<'aamva_dts'>(TrustList.AAMVA_DTS);
    expectType<'government_issued_id'>(TrustScope.GOVERNMENT_ISSUED_ID);
    expectType<'document_signing'>(TrustScope.DOCUMENT_SIGNING);
    expectType<'skip'>(RevocationCheckMode.SKIP);
    expectType<'best_effort'>(RevocationCheckMode.BEST_EFFORT);
    expectType<'required'>(RevocationCheckMode.REQUIRED);
    expectType<'certificate_signature_verification_failed'>(UntrustedReason.CERTIFICATE_SIGNATURE_VERIFICATION_FAILED);
    expectType<TrustList>('uv');
    expectType<TrustScope>('document_signing');
    expectType<RevocationCheckMode>('required');
    expectType<UntrustedReason>('certificate_missing');

    const userCertificate: UserTrustedIssuerCertificate = {
        data: issuerPem,
        format: 'pem',
        trust_scopes: [TrustScope.DOCUMENT_SIGNING],
        entity_type: 'educational_institution',
        entity_metadata: { country: 'US' },
        display: { name: 'Example University' },
    };
    const constructorOptions = {
        trustedIssuerCertificates: [issuerPem, userCertificate],
        revocationCheckMode: RevocationCheckMode.REQUIRED,
        timeout: 10000,
        cacheEnabled: true,
        cacheTTL: 86400000,
    } as const satisfies RegistryOptions;
    const registry = new Registry(constructorOptions);
    const options = {
        trustLists: [TrustList.UV, TrustList.AAMVA_DTS],
        trustScope: TrustScope.GOVERNMENT_ISSUED_ID,
    } as const satisfies ResolveCertificateTrustOptions;
    const certificate = parsePemCertificate(certificatePem);
    expectType<Certificate>(certificate);
    expectType<CertificateInput>(certificatePem);
    expectType<CertificateInput>(certificate);
    expectType<string>(certificateToPem(certificate));
    expectType<string>(Registry.minorVersion);

    const result = await registry.resolveCertificateTrust(certificate, options);
    expectType<CertificateTrustResult>(result);
    if(result.trusted) {
        expectType<ResolvedIssuer>(result.issuer);
        expectType<string>(result.issuer.display.name);
        expectType<undefined>(result.untrustedReasons);
    } else {
        expectType<ResolvedIssuer | undefined>(result.issuer);
        expectType<UntrustedReason[]>(result.untrustedReasons);
    }
    for(const candidate of result.issuer?.certificates || []) {
        expectType<ResolvedIssuerCertificate>(candidate);
        expectType<IssuerCertificate>(candidate);
        expectType<RevocationStatus>(candidate.revocationStatus);
        expectType<UntrustedReason[] | undefined>(candidate.untrustedReasons);
    }

    await registry.resolveCertificateTrust(certificatePem);
    await registry.resolveCertificateTrust(new Certificate());
    await registry.resolveCertificateTrust(null);
    await registry.resolveCertificateTrust(undefined);
    await registry.resolveCertificateTrust();
    await registry.resolveCertificateTrust(certificate, { trustLists: [], trustScope: null });
    await registry.resolveCertificateTrust(certificate, { trustScope: undefined });
    expectType<Issuer | null>(await registry.getIssuerFromX509AKI('example-aki'));
    expectType<Date | null>(await registry.getEndOfLifeDate());
    expectType<boolean>(await verifyCertificateSignature(certificate, issuerPem));
    expectType<boolean>(await verifyCertificateSignature(certificatePem, parsePemCertificate(issuerPem)));
    expectType<boolean>(await verifySignatureWithPem(issuerPem, signature, new ArrayBuffer(1)));
    expectType<boolean>(await verifySignatureWithPem(issuerPem, signature, new Uint8Array(1)));
    expectType<boolean>(await verifySignatureWithPem(issuerPem, signature, new DataView(new ArrayBuffer(1))));

    const issuer: Issuer = {
        issuer_id: 'x509_aki:example',
        entity_type: 'government',
        entity_metadata: {},
        display: { name: 'Example issuer' },
        trust_scopes: [],
        certificates: [],
    };
    expectType<EntityType>(issuer.entity_type);
    expectType<EntityMetadata>(issuer.entity_metadata);
    expectType<IssuerDisplay>(issuer.display);
    expectType<string | undefined>(issuer.signature);
    expectType<CertificateTrustResult>({ trusted: false, untrustedReasons: [UntrustedReason.CERTIFICATE_MISSING] });

    for(const BuiltRegistry of [UnbundledRegistry, MinifiedRegistry, BundledRegistry, BundledMinifiedRegistry]) {
        expectType<Registry>(new BuiltRegistry(constructorOptions));
        expectType<CertificateTrustResult>(await new BuiltRegistry().resolveCertificateTrust(certificatePem));
    }

    // @ts-expect-error Certificate objects need PEM data.
    new Registry({ trustedIssuerCertificates: [{}] });
    // @ts-expect-error DER is not a supported issuer certificate format.
    new Registry({ trustedIssuerCertificates: [{ data: issuerPem, format: 'der' }] });
    // @ts-expect-error Revocation modes are limited to the exported values.
    new Registry({ revocationCheckMode: 'strict' });
    // @ts-expect-error Timeouts are specified as numbers.
    new Registry({ timeout: '10000' });
    // @ts-expect-error Raw DER is not accepted by the resolver.
    registry.resolveCertificateTrust(new Uint8Array(1));
    // @ts-expect-error PEM wrapper objects are not resolver inputs.
    registry.resolveCertificateTrust({ data: certificatePem, format: 'pem' });
    // @ts-expect-error Registry trust lists must use supported values.
    registry.resolveCertificateTrust(certificate, { trustLists: ['user_provided'] });
    // @ts-expect-error Trust scopes must use supported values.
    registry.resolveCertificateTrust(certificate, { trustScope: 'identity_document' });
    // @ts-expect-error Issuer lookups take a string AKI.
    registry.getIssuerFromX509AKI(123);
    // @ts-expect-error PEM parsing takes a string.
    parsePemCertificate(new Uint8Array(1));
    // @ts-expect-error Serialization takes a parsed certificate.
    certificateToPem(certificatePem);
    // @ts-expect-error Data signatures are checked against bytes, not text.
    verifySignatureWithPem(issuerPem, signature, 'signed text');
    // @ts-expect-error A trusted result always includes its issuer.
    expectType<CertificateTrustResult>({ trusted: true });
    // @ts-expect-error An untrusted result always includes failure reasons.
    expectType<CertificateTrustResult>({ trusted: false });
    // @ts-expect-error Human-readable messages are not reason codes.
    expectType<UntrustedReason>('Certificate is expired');
    // @ts-expect-error Returned display names cannot be undefined.
    expectType<IssuerDisplay>({ name: undefined });
    // @ts-expect-error Optional metadata output fields are omitted rather than set to undefined.
    expectType<EntityMetadata>({ country: undefined });
    // @ts-expect-error Trust results do not contain a registry signature.
    result.issuer!.signature;
}
