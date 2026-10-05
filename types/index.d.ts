/// <reference lib="dom" />

import type { Certificate } from 'pkijs';

export const TrustList: {
    readonly UV: 'uv';
    readonly AAMVA_DTS: 'aamva_dts';
};
export type TrustList = typeof TrustList[keyof typeof TrustList];

export const TrustScope: {
    readonly GOVERNMENT_ISSUED_ID: 'government_issued_id';
    readonly DOCUMENT_SIGNING: 'document_signing';
};
export type TrustScope = typeof TrustScope[keyof typeof TrustScope];

export const RevocationCheckMode: {
    readonly SKIP: 'skip';
    readonly BEST_EFFORT: 'best_effort';
    readonly REQUIRED: 'required';
};
export type RevocationCheckMode = typeof RevocationCheckMode[keyof typeof RevocationCheckMode];

export const UntrustedReason: {
    readonly CERTIFICATE_MISSING: 'certificate_missing';
    readonly CERTIFICATE_AKI_MISSING: 'certificate_aki_missing';
    readonly CERTIFICATE_NOT_YET_VALID: 'certificate_not_yet_valid';
    readonly CERTIFICATE_EXPIRED: 'certificate_expired';
    readonly CERTIFICATE_REVOKED: 'certificate_revoked';
    readonly REVOCATION_STATUS_UNDETERMINED: 'revocation_status_undetermined';
    readonly ISSUER_FETCH_FAILED: 'issuer_fetch_failed';
    readonly ISSUER_CERTIFICATE_NOT_FOUND: 'issuer_certificate_not_found';
    readonly CERTIFICATE_SIGNATURE_VERIFICATION_FAILED: 'certificate_signature_verification_failed';
    readonly ISSUER_CERTIFICATE_NOT_YET_VALID: 'issuer_certificate_not_yet_valid';
    readonly ISSUER_CERTIFICATE_EXPIRED: 'issuer_certificate_expired';
    readonly ISSUER_CERTIFICATE_NOT_IN_TRUST_LISTS: 'issuer_certificate_not_in_trust_lists';
    readonly ISSUER_MISSING_REQUIRED_TRUST_SCOPE: 'issuer_missing_required_trust_scope';
};
export type UntrustedReason = typeof UntrustedReason[keyof typeof UntrustedReason];

export type EntityType =
    | 'government'
    | 'educational_institution'
    | 'commercial'
    | 'non_profit'
    | 'international_body'
    | 'other';

export type CertificateInput = string | Certificate;
export type RevocationStatus = 'not_checked' | 'not_revoked' | 'revoked';

export interface EntityMetadata {
    country?: string;
    region?: string;
}

export interface IssuerDisplay {
    name: string;
    logo?: string;
    description?: string;
}

type OptionalInputFields<T> = {
    [Key in keyof T]?: T[Key] | undefined;
};

export interface UserTrustedIssuerCertificate {
    data: string;
    format?: 'pem' | undefined;
    trust_scopes?: readonly TrustScope[] | undefined;
    entity_type?: EntityType | undefined;
    entity_metadata?: OptionalInputFields<EntityMetadata> | undefined;
    display?: OptionalInputFields<IssuerDisplay> | undefined;
}

export interface RegistryOptions {
    trustedIssuerCertificates?: readonly (string | UserTrustedIssuerCertificate)[] | undefined;
    /** @default 'skip' */
    revocationCheckMode?: RevocationCheckMode | undefined;
    /** Per-request timeout in milliseconds, including downloading the response body. @default 10000 */
    timeout?: number | undefined;
    /** @default true */
    cacheEnabled?: boolean | undefined;
    /** Cache lifetime in milliseconds. @default 86400000 */
    cacheTTL?: number | undefined;
}

export interface ResolveCertificateTrustOptions {
    /** An empty array uses only user-provided issuers. @default [] */
    trustLists?: readonly TrustList[] | undefined;
    /** Omitted, undefined, or null skips scope checking. */
    trustScope?: TrustScope | null | undefined;
}

export interface IssuerCertificate {
    data: string;
    format: 'pem';
    trust_lists: (TrustList | 'user_provided')[];
}

export interface Issuer {
    issuer_id: string;
    entity_type: EntityType;
    entity_metadata: EntityMetadata;
    display: IssuerDisplay;
    trust_scopes: TrustScope[];
    certificates: IssuerCertificate[];
    /** Present only on an unmerged registry issuer. */
    signature?: string;
}

export interface ResolvedIssuerCertificate extends IssuerCertificate {
    trusted: boolean;
    revocationStatus: RevocationStatus;
    untrustedReasons?: UntrustedReason[];
}

export interface ResolvedIssuer extends Omit<Issuer, 'certificates' | 'signature'> {
    certificates: ResolvedIssuerCertificate[];
}

export type CertificateTrustResult =
    | {
        trusted: true;
        issuer: ResolvedIssuer;
        untrustedReasons?: never;
    }
    | {
        trusted: false;
        issuer?: ResolvedIssuer;
        untrustedReasons: UntrustedReason[];
    };

export class Registry {
    constructor(options?: RegistryOptions);
    static minorVersion: string;
    getEndOfLifeDate(): Promise<Date | null>;
    getIssuerFromX509AKI(x509aki: string): Promise<Issuer | null>;
    resolveCertificateTrust(
        certificate?: CertificateInput | null,
        options?: ResolveCertificateTrustOptions,
    ): Promise<CertificateTrustResult>;
}

export function parsePemCertificate(pemString: string): Certificate;
export function certificateToPem(certificate: Certificate): string;
export function verifyCertificateSignature(
    certificate: CertificateInput,
    issuerCertificate: CertificateInput,
): Promise<boolean>;
export function verifySignatureWithPem(
    pemKey: string,
    signature: string,
    data: ArrayBuffer | ArrayBufferView,
): Promise<boolean>;
