import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { CachedFetcher } from '../scripts/cached-fetcher.js';

const URL = 'https://example.test/resource';

test('HTTP 404s are automatically cached for every purpose', async t => {
    let calls = 0;
    t.mock.method(globalThis, 'fetch', async () => {
        calls++;
        return new Response(null, { status: 404 });
    });
    const cachedFetcher = new CachedFetcher();
    for(const purpose of ['issuer', 'deprecation', 'crl']) {
        const first = await cachedFetcher.fetch(URL, purpose);
        const second = await cachedFetcher.fetch(URL, purpose);
        assert.equal(first.status, 404);
        assert.equal(second.status, 404);
        assert.equal('bytes' in first, false);
        assert.equal('bytes' in second, false);
    }
    assert.equal(calls, 3);
});

test('HTTP error response bodies are cancelled without consuming them', async t => {
    let status;
    let cancellations = 0;
    const responses = [];
    t.mock.method(globalThis, 'fetch', async () => {
        const response = new Response(new ReadableStream({
            start(controller) { controller.enqueue(new Uint8Array([1, 2, 3])); },
            cancel() { cancellations++; },
        }), { status });
        responses.push(response);
        t.mock.method(response, 'arrayBuffer', async () => { throw new Error('Error bodies must not be downloaded'); });
        return response;
    });
    const cachedFetcher = new CachedFetcher();
    for(const purpose of ['issuer', 'deprecation', 'crl']) {
        for(status of [404, 503]) {
            const url = `${URL}/${status}`;
            assert.equal((await cachedFetcher.fetch(url, purpose)).status, status);
            assert.equal((await responses.at(-1).body.getReader().read()).done, true);
        }
    }
    assert.equal(cancellations, 6);
    for(const response of responses) assert.equal(response.arrayBuffer.mock.callCount(), 0);
});

test('HTTP error body cancellation is included in the request timeout', async t => {
    t.mock.timers.enable({ apis: ['setTimeout'] });
    const cancellation = deferred();
    let signal;
    let cancellations = 0;
    t.mock.method(globalThis, 'fetch', async (_url, options) => {
        signal = options.signal;
        signal.addEventListener('abort', () => cancellation.reject(new DOMException('Aborted', 'AbortError')));
        return {
            ok: false,
            status: 404,
            body: { cancel: () => { cancellations++; return cancellation.promise; } },
        };
    });
    const cachedFetcher = new CachedFetcher({ timeout: 10 });
    const rejection = assert.rejects(cachedFetcher.fetch(URL, 'issuer'), { name: 'TimeoutError' });
    await Promise.resolve();
    assert.equal(cancellations, 1);
    t.mock.timers.tick(10);
    await rejection;
    assert.equal(signal.aborted, true);
    assert.equal(cachedFetcher._inFlight.size, 0);
    assert.equal(cachedFetcher._cache.size, 0);
});

test('default cache TTL is 24 hours and zero TTL retains no results', async t => {
    let now = 1000;
    let calls = 0;
    t.mock.method(Date, 'now', () => now);
    t.mock.method(globalThis, 'fetch', async () => {
        calls++;
        return new Response('{"version":"0.2"}');
    });
    const cachedFetcher = new CachedFetcher();
    await cachedFetcher.fetch(URL, 'deprecation');
    now += 24 * 60 * 60 * 1000 - 1;
    await cachedFetcher.fetch(URL, 'deprecation');
    assert.equal(calls, 1);
    now++;
    await cachedFetcher.fetch(URL, 'deprecation');
    assert.equal(calls, 2);

    const zeroTTL = new CachedFetcher({ cacheTTL: 0 });
    await zeroTTL.fetch(URL, 'deprecation');
    await zeroTTL.fetch(URL, 'deprecation');
    assert.equal(calls, 4);
});

test('cache retains at most 1024 responses across purposes and evicts the least recently used', async t => {
    let calls = 0;
    t.mock.method(globalThis, 'fetch', async () => {
        calls++;
        return new Response(null, { status: 404 });
    });
    const cachedFetcher = new CachedFetcher();
    const purposes = ['issuer', 'deprecation', 'crl'];
    for(let i = 0; i < 1024; i++) {
        await cachedFetcher.fetch(`${URL}/${i}`, purposes[i % purposes.length]);
    }
    assert.equal(cachedFetcher._cache.size, 1024);
    await cachedFetcher.fetch(`${URL}/0`, 'issuer');
    await cachedFetcher.fetch(`${URL}/1024`, 'issuer');
    assert.equal(cachedFetcher._cache.size, 1024);
    assert.equal(cachedFetcher._cache.has(`issuer:${URL}/0`), true);
    assert.equal(cachedFetcher._cache.has(`deprecation:${URL}/1`), false);
    await cachedFetcher.fetch(`${URL}/0`, 'issuer');
    assert.equal(calls, 1025);
    await cachedFetcher.fetch(`${URL}/1`, 'deprecation');
    assert.equal(calls, 1026);
    assert.equal(cachedFetcher._cache.size, 1024);
});

test('replacing a cached response refreshes its recency without evicting another entry', () => {
    const cachedFetcher = new CachedFetcher();
    for(let i = 0; i < 1024; i++) cachedFetcher._set('issuer', `${URL}/${i}`, { status: 404 });
    const replacement = { status: 404, marker: 'updated' };
    cachedFetcher._set('issuer', `${URL}/0`, replacement);
    assert.equal(cachedFetcher._cache.size, 1024);
    assert.equal(cachedFetcher._cache.has(`issuer:${URL}/1`), true);
    assert.equal(cachedFetcher._get('issuer', `${URL}/0`), replacement);
    cachedFetcher._set('issuer', `${URL}/1024`, { status: 404 });
    assert.equal(cachedFetcher._cache.has(`issuer:${URL}/0`), true);
    assert.equal(cachedFetcher._cache.has(`issuer:${URL}/1`), false);
});

test('cache activity sweeps unrelated expired entries at most once per minute even with a short TTL', async t => {
    let now = 1000;
    t.mock.method(Date, 'now', () => now);
    t.mock.method(globalThis, 'fetch', async () => new Response(null, { status: 404 }));
    const cachedFetcher = new CachedFetcher({ cacheTTL: 10 });
    await cachedFetcher.fetch(`${URL}/old-issuer`, 'issuer');
    await cachedFetcher.fetch(`${URL}/old-crl`, 'crl');
    now += 11;
    await cachedFetcher.fetch(`${URL}/recent`, 'deprecation');
    assert.equal(cachedFetcher._cache.size, 3);
    assert.equal(cachedFetcher._lastCacheSweepAt, 1000);
    now = 61000;
    assert.equal(cachedFetcher._cache.size, 3);
    await cachedFetcher.fetch(`${URL}/new`, 'issuer');
    assert.equal(cachedFetcher._cache.size, 1);
    assert.equal(cachedFetcher._lastCacheSweepAt, 61000);
    now += 11;
    await cachedFetcher.fetch(`${URL}/another`, 'crl');
    assert.equal(cachedFetcher._cache.size, 2);
    assert.equal(cachedFetcher._lastCacheSweepAt, 61000);
});

test('cache hits sweep expired entries without extending live entries TTL', async t => {
    let now = 1000;
    t.mock.method(Date, 'now', () => now);
    t.mock.method(globalThis, 'fetch', async () => { throw new Error('Live cache entry must not be fetched'); });
    const cachedFetcher = new CachedFetcher({ cacheTTL: 120000 });
    const liveResponse = { ok: false, status: 404, issuer: null };
    cachedFetcher._set('crl', `${URL}/expired`, { status: 404 }, { expiresAt: now + 10 });
    cachedFetcher._set('issuer', `${URL}/live`, liveResponse);
    now += 60000;
    assert.equal(await cachedFetcher.fetch(`${URL}/live`, 'issuer'), liveResponse);
    assert.equal(cachedFetcher._cache.size, 1);
    assert.equal(cachedFetcher._cache.get(`issuer:${URL}/live`).expiresAt, 121000);
});

test('completed downloads trigger expiry cleanup before cache admission', async t => {
    let now = 1000;
    t.mock.method(Date, 'now', () => now);
    t.mock.method(globalThis, 'fetch', async () => {
        now += 60000;
        return new Response(null, { status: 404 });
    });
    const cachedFetcher = new CachedFetcher();
    cachedFetcher._set('crl', `${URL}/expired`, { status: 404 }, { expiresAt: now + 10 });
    await cachedFetcher.fetch(`${URL}/new`, 'issuer');
    assert.equal(cachedFetcher._cache.size, 1);
    assert.equal(cachedFetcher._cache.has(`crl:${URL}/expired`), false);
    assert.equal(cachedFetcher._lastCacheSweepAt, 61000);
});

test('disabled caching never invokes expiry cleanup or retains responses', async t => {
    let now = 1000;
    t.mock.method(Date, 'now', () => now);
    t.mock.method(globalThis, 'fetch', async () => new Response(null, { status: 404 }));
    const cachedFetcher = new CachedFetcher({ cacheEnabled: false });
    const sweep = t.mock.method(cachedFetcher, '_sweepExpiredEntries');
    now += 60000;
    for(const purpose of ['issuer', 'deprecation', 'crl']) await cachedFetcher.fetch(URL, purpose);
    assert.equal(sweep.mock.callCount(), 0);
    assert.equal(cachedFetcher._cache.size, 0);
});

test('cache maintenance schedules no background or per-entry timers', t => {
    let now = 1000;
    t.mock.method(Date, 'now', () => now);
    t.mock.method(globalThis, 'setTimeout', () => { throw new Error('Cache maintenance must not schedule timers'); });
    t.mock.method(globalThis, 'setInterval', () => { throw new Error('Cache maintenance must not schedule timers'); });
    const cachedFetcher = new CachedFetcher({ cacheTTL: 10 });
    cachedFetcher._set('issuer', URL, { status: 404 });
    now += 60000;
    assert.equal(cachedFetcher._get('issuer', URL), undefined);
    assert.equal(cachedFetcher._cache.size, 0);
});

test('shared downloads are admitted independently for each purpose', async t => {
    let calls = 0;
    t.mock.method(globalThis, 'fetch', async () => {
        calls++;
        return new Response(null, { status: 404 });
    });
    const cachedFetcher = new CachedFetcher();
    await Promise.all([
        cachedFetcher.fetch(URL, 'deprecation'),
        cachedFetcher.fetch(URL, 'crl'),
    ]);
    assert.equal(calls, 1);
    await cachedFetcher.fetch(URL, 'deprecation');
    await cachedFetcher.fetch(URL, 'crl');
    assert.equal(calls, 1);
    await cachedFetcher.fetch(URL, 'issuer');
    assert.equal(calls, 2);
});

test('deprecation cache hits reuse parsed content without retaining response bytes', async t => {
    let calls = 0;
    const notice = { version: '0.2', end_of_life: 1761782400 };
    t.mock.method(globalThis, 'fetch', async () => {
        calls++;
        return new Response(JSON.stringify(notice));
    });
    const cachedFetcher = new CachedFetcher();
    const first = await cachedFetcher.fetch(URL, 'deprecation');
    const cached = await cachedFetcher.fetch(URL, 'deprecation');
    assert.deepEqual(first.deprecationNotice, notice);
    assert.equal(cached.deprecationNotice, first.deprecationNotice);
    assert.equal('bytes' in first, false);
    assert.equal('bytes' in cached, false);
    assert.equal(calls, 1);
});

test('concurrent callers share downloads through body consumption even with caching disabled', async t => {
    const cachedFetcher = new CachedFetcher({ cacheEnabled: false });
    const body = deferred();
    let calls = 0;
    let bodyReads = 0;
    t.mock.method(globalThis, 'fetch', async () => {
        calls++;
        return {
            ok: true,
            status: 200,
            statusText: 'OK',
            arrayBuffer: async () => {
                bodyReads++;
                return body.promise;
            },
        };
    });

    const first = cachedFetcher.fetch(URL, 'deprecation');
    await Promise.resolve();
    const second = cachedFetcher.fetch(URL, 'crl');
    body.resolve(new TextEncoder().encode('{"name":"Example"}').buffer);
    const [noticeDownload, crlDownload] = await Promise.all([first, second]);
    assert.equal(calls, 1);
    assert.equal(bodyReads, 1);
    assert.equal(noticeDownload.status, 200);
    assert.deepEqual(noticeDownload.deprecationNotice, { name: 'Example' });
    assert.equal(typeof crlDownload.error, 'string');
    assert.equal('bytes' in noticeDownload, false);
    assert.equal('bytes' in crlDownload, false);
    await cachedFetcher.fetch(URL, 'deprecation');
    assert.equal(calls, 2);
    assert.equal(bodyReads, 2);
});

test('issuer responses are cached only after successful signature verification', async t => {
    const fixture = JSON.parse(readFileSync(new globalThis.URL('../issuers/x509_aki/taXH_AFcuSnQgLECaiofOquMVcQ.json', import.meta.url), 'utf8'));
    let calls = 0;
    let verifications = 0;
    t.mock.method(globalThis, 'fetch', async () => {
        calls++;
        return new Response(JSON.stringify(fixture));
    });
    t.mock.method(crypto.subtle, 'verify', async () => ++verifications > 1);
    const cachedFetcher = new CachedFetcher();

    assert.equal((await cachedFetcher.fetch(URL, 'issuer')).issuer, null);
    const valid = await cachedFetcher.fetch(URL, 'issuer');
    const cached = await cachedFetcher.fetch(URL, 'issuer');
    assert.deepEqual(valid.issuer, fixture);
    assert.equal(cached.issuer, valid.issuer);
    assert.equal('bytes' in valid, false);
    assert.equal('bytes' in cached, false);
    assert.equal(calls, 2);
    assert.equal(verifications, 2);
});

test('malformed issuer JSON is not cached', async t => {
    let calls = 0;
    t.mock.method(globalThis, 'fetch', async () => {
        calls++;
        return new Response('Malformed JSON');
    });
    const cachedFetcher = new CachedFetcher();
    await assert.rejects(cachedFetcher.fetch(URL, 'issuer'), SyntaxError);
    await assert.rejects(cachedFetcher.fetch(URL, 'issuer'), SyntaxError);
    assert.equal(calls, 2);
});

test('malformed CRL documents are cached until the normal TTL', async t => {
    let now = 1000;
    let calls = 0;
    t.mock.method(Date, 'now', () => now);
    t.mock.method(globalThis, 'fetch', async () => {
        calls++;
        return new Response('Not a CRL');
    });
    const cachedFetcher = new CachedFetcher({ cacheTTL: 100 });
    const first = await cachedFetcher.fetch(URL, 'crl');
    assert.equal(first.ok, true);
    assert.equal(typeof first.error, 'string');
    assert.equal('bytes' in first, false);
    assert.deepEqual(await cachedFetcher.fetch(URL, 'crl'), first);
    assert.equal(calls, 1);
    now += 100;
    await cachedFetcher.fetch(URL, 'crl');
    assert.equal(calls, 2);
});

test('HTTP errors other than 404 are not cached for any purpose', async t => {
    let calls = 0;
    let status;
    t.mock.method(globalThis, 'fetch', async () => {
        calls++;
        return new Response('Unavailable', { status });
    });
    const cachedFetcher = new CachedFetcher();
    for(const purpose of ['issuer', 'deprecation', 'crl']) {
        for(status of [400, 401, 403, 429, 500, 503]) {
            for(let attempt = 0; attempt < 2; attempt++) {
                const result = await cachedFetcher.fetch(URL, purpose);
                assert.equal(result.status, status);
                assert.equal('bytes' in result, false);
            }
        }
    }
    assert.equal(calls, 36);
});

test('failed shared downloads are removed and subsequent requests can retry', async t => {
    const cachedFetcher = new CachedFetcher();
    let calls = 0;
    t.mock.method(globalThis, 'fetch', async () => {
        calls++;
        if(calls === 1) throw new Error('Network unavailable');
        return new Response('{"message":"Success"}');
    });

    const results = await Promise.allSettled([
        cachedFetcher.fetch(URL, 'deprecation'),
        cachedFetcher.fetch(URL, 'crl'),
    ]);
    assert.equal(calls, 1);
    for(const result of results) {
        assert.equal(result.status, 'rejected');
        assert.match(result.reason.message, /Network unavailable/);
    }
    assert.deepEqual((await cachedFetcher.fetch(URL, 'deprecation')).deprecationNotice, { message: 'Success' });
    assert.equal(calls, 2);
});

test('a failed response body read is not cached even after successful headers', async t => {
    let calls = 0;
    t.mock.method(globalThis, 'fetch', async () => {
        calls++;
        if(calls === 1) {
            return { ok: true, arrayBuffer: async () => { throw new Error('Body download failed'); } };
        }
        return new Response('{"message":"Success"}');
    });
    const cachedFetcher = new CachedFetcher();
    await assert.rejects(cachedFetcher.fetch(URL, 'deprecation'), /Body download failed/);
    await cachedFetcher.fetch(URL, 'deprecation');
    assert.equal(calls, 2);
});

test('the default timeout aborts an unfinished download after 10 seconds', async t => {
    t.mock.timers.enable({ apis: ['setTimeout'] });
    let signal;
    t.mock.method(globalThis, 'fetch', async (_url, options) => {
        signal = options.signal;
        return new Promise((_resolve, reject) => {
            signal.addEventListener('abort', () => reject(new DOMException('Aborted', 'AbortError')));
        });
    });
    const cachedFetcher = new CachedFetcher();
    const rejection = assert.rejects(cachedFetcher.fetch(URL, 'deprecation'), {
        name: 'TimeoutError',
        message: 'Request timed out after 10000ms',
    });
    t.mock.timers.tick(9999);
    assert.equal(signal.aborted, false);
    t.mock.timers.tick(1);
    await rejection;
    assert.equal(signal.aborted, true);
});

test('one caller timing out does not cancel a later caller sharing the URL', async t => {
    t.mock.timers.enable({ apis: ['setTimeout'] });
    const cachedFetcher = new CachedFetcher({ timeout: 10 });
    const body = deferred();
    let signal;
    let calls = 0;
    t.mock.method(globalThis, 'fetch', async (_url, options) => {
        calls++;
        signal = options.signal;
        return { ok: true, arrayBuffer: async () => body.promise };
    });

    const rejection = assert.rejects(cachedFetcher.fetch(URL, 'crl'), {
        name: 'TimeoutError', message: 'Request timed out after 10ms',
    });
    t.mock.timers.tick(5);
    const noticeRequest = cachedFetcher.fetch(URL, 'deprecation');
    t.mock.timers.tick(5);
    await rejection;
    assert.equal(signal.aborted, false);
    body.resolve(new TextEncoder().encode('{"message":"Success"}').buffer);
    assert.deepEqual((await noticeRequest).deprecationNotice, { message: 'Success' });
    assert.equal(calls, 1);
});

test('a timed-out download is aborted and its late cleanup cannot remove a retry', async t => {
    t.mock.timers.enable({ apis: ['setTimeout'] });
    const cachedFetcher = new CachedFetcher({ timeout: 10 });
    const abandoned = deferred();
    const retryBody = deferred();
    let firstSignal;
    let calls = 0;
    t.mock.method(globalThis, 'fetch', async (_url, options) => {
        calls++;
        if(calls === 1) {
            firstSignal = options.signal;
            return abandoned.promise;
        }
        return { ok: true, arrayBuffer: async () => retryBody.promise };
    });

    const rejection = assert.rejects(cachedFetcher.fetch(URL, 'deprecation'), { name: 'TimeoutError' });
    t.mock.timers.tick(10);
    await rejection;
    assert.equal(firstSignal.aborted, true);
    const retry = cachedFetcher.fetch(URL, 'deprecation');
    abandoned.reject(new DOMException('Aborted', 'AbortError'));
    await new Promise(resolve => setImmediate(resolve));
    const joinedRetry = cachedFetcher.fetch(URL, 'deprecation');
    retryBody.resolve(new TextEncoder().encode('{"message":"Success"}').buffer);
    await Promise.all([retry, joinedRetry]);
    assert.equal(calls, 2);
});

test('the timeout includes downloading the response body and timed-out responses are not cached', async t => {
    t.mock.timers.enable({ apis: ['setTimeout'] });
    const body = deferred();
    let signal;
    let calls = 0;
    t.mock.method(globalThis, 'fetch', async (_url, options) => {
        calls++;
        signal = options.signal;
        if(calls > 1) return new Response('{"message":"Success"}');
        signal.addEventListener('abort', () => body.reject(new DOMException('Aborted', 'AbortError')));
        return { ok: true, arrayBuffer: async () => body.promise };
    });
    const cachedFetcher = new CachedFetcher({ timeout: 10 });
    const rejection = assert.rejects(cachedFetcher.fetch(URL, 'deprecation'), { name: 'TimeoutError' });
    await Promise.resolve();
    t.mock.timers.tick(10);
    await rejection;
    assert.equal(signal.aborted, true);
    await cachedFetcher.fetch(URL, 'deprecation');
    assert.equal(calls, 2);
});

function deferred() {
    let resolve;
    let reject;
    const promise = new Promise((fulfill, fail) => { resolve = fulfill; reject = fail; });
    return { promise, resolve, reject };
}
