import { verifyIssuer } from './issuer-helper.js';
import { parseCRL } from './crl-helper.js';

const MAX_CACHE_ENTRIES = 1024;
const CACHE_SWEEP_INTERVAL = 60 * 1000;

export class CachedFetcher {
    constructor(options = {}) {
        this.cacheEnabled = options.cacheEnabled ?? true;
        this._cacheTTL = options.cacheTTL ?? 1000 * 60 * 60 * 24;
        this._timeout = options.timeout ?? 10000;
        this._cache = new Map();
        this._inFlight = new Map();
        this._lastCacheSweepAt = Date.now();
    }

    async fetch(url, purpose) {
        const cached = this._get(purpose, url);
        if(cached !== undefined) return cached;

        const response = await this._fetch(url);
        switch(purpose) {
            case 'issuer': return this._cacheIssuerResponse(url, response);
            case 'deprecation': return this._cacheDeprecationResponse(url, response);
            case 'crl': return this._cacheCRLResponse(url, response);
            default: throw new Error(`Unsupported fetch purpose: ${purpose}`);
        }
    }

    _get(purpose, url) {
        if(!this.cacheEnabled) return undefined;
        const now = Date.now();
        this._sweepExpiredEntries(now);
        const key = `${purpose}:${url}`;
        const cached = this._cache.get(key);
        if(!cached) return undefined;
        if(cached.expiresAt <= now) {
            this._cache.delete(key);
            return undefined;
        }
        this._cache.delete(key);
        this._cache.set(key, cached);
        return cached.value;
    }

    _set(purpose, url, value, options = {}) {
        if(!this.cacheEnabled) return;
        const now = Date.now();
        this._sweepExpiredEntries(now);
        const expiresAt = Math.min(now + this._cacheTTL, options.expiresAt ?? Infinity);
        const key = `${purpose}:${url}`;
        if(expiresAt <= now) {
            this._cache.delete(key);
            return;
        }
        this._cache.delete(key);
        this._cache.set(key, { value, expiresAt });
        if(this._cache.size > MAX_CACHE_ENTRIES) {
            this._cache.delete(this._cache.keys().next().value);
        }
    }

    _sweepExpiredEntries(now) {
        if(now - this._lastCacheSweepAt < CACHE_SWEEP_INTERVAL) return;
        this._lastCacheSweepAt = now;
        for(const [key, cached] of this._cache) {
            if(cached.expiresAt <= now) this._cache.delete(key);
        }
    }

    async _cacheIssuerResponse(url, { bytes, ...result }) {
        result.issuer = null;
        if(result.ok) {
            const issuer = JSON.parse(new TextDecoder().decode(bytes));
            if(await verifyIssuer(issuer)) result.issuer = issuer;
        }
        if(result.issuer || result.status === 404) this._set('issuer', url, result);
        return result;
    }

    _cacheDeprecationResponse(url, { bytes, ...result }) {
        if(result.ok) {
            try {
                result.deprecationNotice = JSON.parse(new TextDecoder().decode(bytes));
            } catch(error) {
                result.error = error.message;
            }
        }
        if(result.ok || result.status === 404) this._set('deprecation', url, result);
        return result;
    }

    _cacheCRLResponse(url, { bytes, ...result }) {
        if(result.ok) {
            try {
                result.crl = parseCRL(bytes);
            } catch(error) {
                // A completed download is reusable even when its contents are malformed.
                result.error = error.message;
            }
        }
        const nextUpdate = result.crl?.nextUpdate?.value.getTime();
        if(result.ok || result.status === 404) {
            this._set('crl', url, result, {
                expiresAt: nextUpdate > Date.now() ? nextUpdate : undefined,
            });
        }
        return result;
    }

    async _fetch(url) {
        let request = this._inFlight.get(url);
        if(!request) {
            const controller = new AbortController();
            request = { controller, consumers: 0 };
            request.promise = this._download(url, controller.signal).finally(() => {
                if(this._inFlight.get(url) === request) this._inFlight.delete(url);
            });
            this._inFlight.set(url, request);
        }

        request.consumers++;
        let timeoutId;
        try {
            return await Promise.race([
                request.promise,
                new Promise((_resolve, reject) => {
                    timeoutId = setTimeout(() => {
                        const error = new Error(`Request timed out after ${this._timeout}ms`);
                        error.name = 'TimeoutError';
                        reject(error);
                    }, this._timeout);
                }),
            ]);
        } finally {
            clearTimeout(timeoutId);
            request.consumers--;
            // A caller's timeout must not cancel other callers sharing the download.
            if(request.consumers === 0 && this._inFlight.get(url) === request) {
                this._inFlight.delete(url);
                request.controller.abort();
            }
        }
    }

    async _download(url, signal) {
        const response = await fetch(url, { signal });
        const bytes = response.ok ? new Uint8Array(await response.arrayBuffer()) : null;
        if(!response.ok) await response.body?.cancel();
        return {
            ok: response.ok,
            status: response.status,
            statusText: response.statusText || '',
            bytes,
        };
    }
}
