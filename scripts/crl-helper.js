import * as asn1js from 'asn1js';
import {
    BasicConstraints,
    Certificate,
    CertificateRevocationList,
    CRLDistributionPoints,
    IssuingDistributionPoint,
} from 'pkijs';
import { ensurePKIjsCryptoEngine, parsePemCertificate } from './certificate-helper.js';
import { base64ToUint8Array } from './utils.js';

const BASIC_CONSTRAINTS_OID = '2.5.29.19';
const KEY_USAGE_OID = '2.5.29.15';
const CRL_REASON_OID = '2.5.29.21';
const DELTA_CRL_INDICATOR_OID = '2.5.29.27';
const ISSUING_DISTRIBUTION_POINT_OID = '2.5.29.28';
const CRL_DISTRIBUTION_POINTS_OID = '2.5.29.31';
const CRL_PEM_BEGIN = '-----BEGIN X509 CRL-----';
const CRL_PEM_END = '-----END X509 CRL-----';
const ALL_REASONS_MASK = 0x1FE;
const CRL_SIGN_KEY_USAGE_MASK = 0x02;
const REMOVE_FROM_CRL_REASON = 8;

const getCRLDistributionPoints = (certificate) => {
    const extension = certificate?.extensions?.find(ext => ext.extnID === CRL_DISTRIBUTION_POINTS_OID);
    if(!extension) return [];

    const crlDistributionPoints = parseExtensionValue(
        extension,
        CRLDistributionPoints,
        'Unable to parse CRL Distribution Points'
    );

    return crlDistributionPoints.distributionPoints
        .map(distributionPoint => ({
            distributionPoint: distributionPoint,
            urls: getDistributionPointUrls(distributionPoint),
        }))
        .filter(distributionPoint => distributionPoint.urls.length > 0);
};

export const checkCertificateRevocation = async (certificate, issuerCertificate, { cachedFetcher }) => {
    let distributionPoints;
    try {
        distributionPoints = getCRLDistributionPoints(certificate);
    } catch(error) {
        return {
            checked: false,
            revoked: false,
            error: error.message,
        };
    }

    const urls = getAllDistributionPointUrls(distributionPoints);
    const result = {
        checked: false,
        revoked: false,
    };

    if(urls.length === 0) return result;

    const errors = [];
    const supportedDistributionPoints = [];
    for(const distributionPoint of distributionPoints) {
        if(hasDelegatedCRLIssuer(distributionPoint)) {
            errors.push('Delegated CRL issuers are not supported');
        } else {
            supportedDistributionPoints.push(distributionPoint);
        }
    }

    const supportedUrls = getAllDistributionPointUrls(supportedDistributionPoints);
    if(supportedUrls.length === 0) {
        if(errors.length > 0) result.error = errors.join('; ');
        return result;
    }

    let crlIssuerCertificate;
    try {
        crlIssuerCertificate = getIssuerCertificate(issuerCertificate);
        validateCRLIssuerCertificate(crlIssuerCertificate);
    } catch(error) {
        result.error = error.message;
        return result;
    }

    const evaluationState = {
        coveredReasonsMask: 0,
        errors: errors,
    };
    const pendingResultsByUrl = getPendingCRLResultsByUrl(supportedUrls, cachedFetcher);

    while(pendingResultsByUrl.size > 0) {
        const crlResult = await getNextCRLResult(pendingResultsByUrl);
        const revocationResult = await evaluateCRLResult(crlResult, supportedDistributionPoints, certificate, crlIssuerCertificate, evaluationState);
        if(revocationResult) {
            return revocationResult;
        }
    }

    if(evaluationState.coveredReasonsMask > 0 && !isCompleteCRLCoverage(evaluationState.coveredReasonsMask)) {
        evaluationState.errors.push('CRL coverage is incomplete');
    }

    if(evaluationState.errors.length > 0) result.error = evaluationState.errors.join('; ');
    return result;
};

const getPendingCRLResultsByUrl = (urls, cachedFetcher) => {
    const pendingResultsByUrl = new Map();

    for(const url of urls) {
        pendingResultsByUrl.set(url, fetchCRL(url, cachedFetcher)
            .then(crl => ({
                url: url,
                crl: crl,
            }))
            .catch(error => ({ url: url, error: error })));
    }

    return pendingResultsByUrl;
};

const getNextCRLResult = async (pendingResultsByUrl) => {
    const result = await Promise.race(pendingResultsByUrl.values());
    pendingResultsByUrl.delete(result.url);
    return result;
};

const evaluateCRLResult = async (crlResult, distributionPoints, certificate, crlIssuerCertificate, state) => {
    const {
        url,
        crl,
        error,
    } = crlResult;

    if(error) {
        state.errors.push(error.message);
        return null;
    }

    try {
        ensurePKIjsCryptoEngine();
        const signatureValid = await crl.verify({
            issuerCertificate: crlIssuerCertificate,
        });
        if(!signatureValid) {
            state.errors.push(`Invalid CRL signature for ${url}`);
            return null;
        }

        const matchingDistributionPoints = distributionPoints.filter(distributionPoint => distributionPoint.urls.includes(url));
        for(const distributionPoint of matchingDistributionPoints) {
            const coverage = getCRLCoverage(certificate, crl, distributionPoint.distributionPoint);
            if(!coverage.coversCertificate) {
                state.errors.push(`${coverage.error} for ${url}`);
                continue;
            }

            if(isCRLNotYetValid(crl)) {
                state.errors.push(`CRL is not yet valid for ${url}`);
                continue;
            }

            const stale = isCRLStale(crl);

            const revokedCertificate = crl.revokedCertificates?.find(entry => entry.userCertificate.isEqual(certificate.serialNumber));
            if(revokedCertificate) {
                if(getCRLEntryReason(revokedCertificate) !== REMOVE_FROM_CRL_REASON) {
                    return {
                        checked: true,
                        revoked: true,
                    };
                }
                if(!isDeltaCRL(crl)) {
                    state.errors.push(`removeFromCRL is only valid in a delta CRL for ${url}`);
                    continue;
                }
            }

            if(isDeltaCRL(crl)) {
                state.errors.push(`Delta CRL cannot establish non-revoked status for ${url}`);
                continue;
            }

            if(!stale) {
                state.coveredReasonsMask |= coverage.reasonsMask;
                if(isCompleteCRLCoverage(state.coveredReasonsMask)) {
                    return {
                        checked: true,
                        revoked: false,
                    };
                }
                continue;
            }

            state.errors.push(`CRL is stale for ${url}`);
        }
    } catch(error) {
        state.errors.push(error.message);
    }

    return null;
};

const getCRLEntryReason = (entry) => {
    const extension = entry.crlEntryExtensions?.extensions.find(ext => ext.extnID === CRL_REASON_OID);
    if(!extension) return null;

    const asn1 = asn1js.fromBER(extension.extnValue.valueBlock.valueHex);
    if(asn1.offset === -1 || !(asn1.result instanceof asn1js.Enumerated)) {
        throw new Error('Unable to parse CRL reason code');
    }
    return asn1.result.valueBlock.valueDec;
};

const getDistributionPointUrls = (distributionPoint) => {
    if(!Array.isArray(distributionPoint.distributionPoint)) return [];

    const urls = [];
    for(const generalName of distributionPoint.distributionPoint) {
        if(generalName.type === 6 && typeof generalName.value === 'string') {
            urls.push(generalName.value);
        }
    }
    return [...new Set(urls)];
};

const hasDelegatedCRLIssuer = (distributionPoint) => {
    return distributionPoint.distributionPoint.cRLIssuer?.length > 0;
};

const getAllDistributionPointUrls = (distributionPoints) => {
    const urls = [];
    for(const distributionPoint of distributionPoints) {
        urls.push(...distributionPoint.urls);
    }
    return [...new Set(urls)];
};

const getIssuerCertificate = (issuerCertificate) => {
    if(issuerCertificate instanceof Certificate) return issuerCertificate;
    if(issuerCertificate?.parsedCertificate instanceof Certificate) return issuerCertificate.parsedCertificate;
    if(typeof issuerCertificate === 'string') return parsePemCertificate(issuerCertificate);
    if(typeof issuerCertificate?.data === 'string') return parsePemCertificate(issuerCertificate.data);
    throw new Error('Issuer certificate is required to verify CRL signature');
};

const validateCRLIssuerCertificate = (issuerCertificate) => {
    if(issuerCertificate.version !== 2) return;

    const keyUsage = issuerCertificate.extensions?.find(ext => ext.extnID === KEY_USAGE_OID);
    if(!keyUsage) throw new Error('CRL issuer certificate key usage does not allow CRL signing');

    const keyUsageValue = asn1js.fromBER(keyUsage.extnValue.valueBlock.valueHex);
    if(keyUsageValue.offset === -1) throw new Error('Unable to parse CRL issuer certificate key usage');

    const keyUsageBytes = new Uint8Array(keyUsageValue.result.valueBlock.valueHexView || keyUsageValue.result.valueBlock.valueHex || []);
    if(!(keyUsageBytes[0] & CRL_SIGN_KEY_USAGE_MASK)) {
        throw new Error('CRL issuer certificate key usage does not allow CRL signing');
    }
};

const getCRLCoverage = (certificate, crl, distributionPoint) => {
    if(!crl.issuer.isEqual(certificate.issuer)) {
        return {
            coversCertificate: false,
            error: 'CRL issuer does not match certificate issuer',
        };
    }

    const issuingDistributionPoint = getIssuingDistributionPoint(crl);
    const issuingDistributionPointCoverage = getIssuingDistributionPointCoverage(
        certificate,
        issuingDistributionPoint,
        distributionPoint
    );
    if(!issuingDistributionPointCoverage.coversCertificate) return issuingDistributionPointCoverage;

    const distributionPointReasons = getReasonMask(distributionPoint.reasons);
    const crlReasons = issuingDistributionPoint?.onlySomeReasons === undefined
        ? ALL_REASONS_MASK
        : getReasonMaskFromBytes(new Uint8Array([issuingDistributionPoint.onlySomeReasons]));
    const reasonsMask = distributionPointReasons & crlReasons;

    if(reasonsMask === 0) {
        return {
            coversCertificate: false,
            error: 'CRL reason scope does not cover certificate distribution point',
        };
    }

    return {
        coversCertificate: true,
        reasonsMask: reasonsMask,
    };
};

const getIssuingDistributionPointCoverage = (certificate, issuingDistributionPoint, distributionPoint) => {
    if(!issuingDistributionPoint) {
        return {
            coversCertificate: true,
        };
    }

    if(issuingDistributionPoint.indirectCRL) {
        return {
            coversCertificate: false,
            error: 'Indirect CRLs are not supported',
        };
    }

    if(issuingDistributionPoint.onlyContainsAttributeCerts) {
        return {
            coversCertificate: false,
            error: 'CRL only covers attribute certificates',
        };
    }

    const certificateIsCA = isCertificateCA(certificate);
    if(issuingDistributionPoint.onlyContainsCACerts && !certificateIsCA) {
        return {
            coversCertificate: false,
            error: 'CRL only covers CA certificates',
        };
    }

    if(issuingDistributionPoint.onlyContainsUserCerts && certificateIsCA) {
        return {
            coversCertificate: false,
            error: 'CRL only covers user certificates',
        };
    }

    if(issuingDistributionPoint.distributionPoint) {
        const crlDistributionPointNames = getDistributionPointNameKeys(issuingDistributionPoint.distributionPoint);
        const certificateDistributionPointNames = getDistributionPointNameKeys(distributionPoint.distributionPoint);
        if(!hasSharedName(crlDistributionPointNames, certificateDistributionPointNames)) {
            return {
                coversCertificate: false,
                error: 'CRL distribution point scope does not match certificate distribution point',
            };
        }
    }

    return {
        coversCertificate: true,
    };
};

const getIssuingDistributionPoint = (crl) => {
    const extension = crl.crlExtensions?.extensions?.find(ext => ext.extnID === ISSUING_DISTRIBUTION_POINT_OID);
    if(!extension) return null;
    return parseExtensionValue(
        extension,
        IssuingDistributionPoint,
        'Unable to parse Issuing Distribution Point'
    );
};

const getReasonMask = (reasons) => {
    if(!reasons) return ALL_REASONS_MASK;
    const bytes = new Uint8Array(reasons.valueBlock.valueHexView || reasons.valueBlock.valueHex || []);
    return getReasonMaskFromBytes(bytes);
};

const getReasonMaskFromBytes = (bytes) => {
    let mask = 0;
    for(let byteIndex = 0; byteIndex < bytes.length; byteIndex++) {
        for(let bitIndex = 0; bitIndex < 8; bitIndex++) {
            if(bytes[byteIndex] & (0x80 >> bitIndex)) {
                mask |= 1 << ((byteIndex * 8) + bitIndex);
            }
        }
    }
    return mask & ALL_REASONS_MASK;
};

const isCompleteCRLCoverage = (reasonsMask) => {
    return (reasonsMask & ALL_REASONS_MASK) === ALL_REASONS_MASK;
};

const isCertificateCA = (certificate) => {
    const extension = certificate?.extensions?.find(ext => ext.extnID === BASIC_CONSTRAINTS_OID);
    if(!extension) return false;

    try {
        const basicConstraints = parseExtensionValue(
            extension,
            BasicConstraints,
            'Unable to parse Basic Constraints'
        );
        return !!basicConstraints.cA;
    } catch(error) {
        return false;
    }
};

const getDistributionPointNameKeys = (distributionPointName) => {
    if(!distributionPointName) return [];
    if(Array.isArray(distributionPointName)) {
        return distributionPointName
            .map(generalName => getGeneralNameKey(generalName));
    }
    if(typeof distributionPointName.toSchema === 'function') {
        return [`rdn:${bufferToHex(distributionPointName.toSchema().toBER(false))}`];
    }
    return [JSON.stringify(distributionPointName)];
};

const getGeneralNameKey = (generalName) => {
    if(generalName?.type === 6 && typeof generalName.value === 'string') {
        return `uri:${generalName.value}`;
    }
    if(typeof generalName?.toSchema === 'function') {
        return `asn1:${bufferToHex(generalName.toSchema().toBER(false))}`;
    }
    return JSON.stringify(generalName);
};

const hasSharedName = (firstNames, secondNames) => {
    if(firstNames.length === 0 || secondNames.length === 0) return false;
    const secondNameSet = new Set(secondNames);
    return firstNames.some(name => secondNameSet.has(name));
};

const bufferToHex = (buffer) => {
    return Array.from(new Uint8Array(buffer), byte => byte.toString(16).padStart(2, '0')).join('');
};

const parseExtensionValue = (extension, ExtensionValue, errorMessage) => {
    if(extension.parsedValue instanceof ExtensionValue) return extension.parsedValue;

    const asn1 = asn1js.fromBER(extension.extnValue.valueBlock.valueHex);
    if(asn1.offset === -1) throw new Error(errorMessage);
    return new ExtensionValue({ schema: asn1.result });
};

const isCRLNotYetValid = (crl) => {
    return crl.thisUpdate.value > new Date();
};

const isCRLStale = (crl) => {
    return !!crl.nextUpdate && crl.nextUpdate.value < new Date();
};

const isDeltaCRL = (crl) => {
    return !!crl.crlExtensions?.extensions?.some(ext => ext.extnID === DELTA_CRL_INDICATOR_OID);
};

const fetchCRL = async (url, cachedFetcher) => {
    const response = await cachedFetcher.fetch(url, 'crl');
    if(!response.ok) {
        throw new Error(`CRL request failed with HTTP ${response.status}`);
    }
    if(response.error) throw new Error(response.error);
    return response.crl;
};

export const parseCRL = (bytes) => {
    const textPrefix = new TextDecoder().decode(bytes.slice(0, CRL_PEM_BEGIN.length + 20));
    const crlBytes = textPrefix.trimStart().startsWith(CRL_PEM_BEGIN)
        ? pemCRLToBytes(new TextDecoder().decode(bytes))
        : bytes;
    const arrayBuffer = crlBytes.buffer.slice(crlBytes.byteOffset, crlBytes.byteOffset + crlBytes.byteLength);
    const asn1 = asn1js.fromBER(arrayBuffer);
    if(asn1.offset === -1) throw new Error('Unable to parse CRL');
    return new CertificateRevocationList({ schema: asn1.result });
};

const pemCRLToBytes = (pem) => {
    const start = pem.indexOf(CRL_PEM_BEGIN);
    const end = pem.indexOf(CRL_PEM_END);
    if(start === -1 || end === -1) throw new Error('Unable to parse PEM CRL');
    const base64 = pem.slice(start + CRL_PEM_BEGIN.length, end).replace(/\s/g, '');
    return base64ToUint8Array(base64);
};
