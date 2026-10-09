const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const { test } = require('node:test');

const html = fs.readFileSync(path.join(__dirname, '../../web/templates/website_detail.html'), 'utf8');
const partial = fs.readFileSync(path.join(__dirname, '../../web/templates/wordpress_cache_status.html'), 'utf8');
const source = [...html.matchAll(/<script[^>]*>([\s\S]*?)<\/script>/g)]
    .map(match => match[1].replace(/{{[\s\S]*?}}/g, 'translated')).join('\n');
const texts = [...partial.matchAll(/<(?:strong|span)\b[^>]*\bx-text="([^"]*)"/g)].map(match => match[1]);
const pageText = texts.find(expression => expression.includes('cacheRuntime.page_cache_enabled'));
const redisText = texts.find(expression => expression.includes('cacheRuntime.redis_object_cache_configured'));
const serverText = texts.find(expression => expression.includes('cacheRuntime.server_cache_state'));
const resultText = texts.find(expression => expression.includes('cache_status.result_'));
const resultClass = [...partial.matchAll(/<span\b[^>]*:class="([^"]*)"/g)]
    .map(match => match[1]).find(expression => expression.includes('cacheVerification?.state'));
const redisEndpoint = [...partial.matchAll(/<span\b[^>]*\bx-show="([^"]*)"[^>]*\bx-text="([^"]*)"/g)]
    .find(match => match[2] === 'redisCacheEndpointText()');
for (const [name, value] of Object.entries({ pageText, redisText, serverText, resultText, resultClass, redisEndpoint })) assert.ok(value, name);

const runtime = (overrides = {}) => ({
    status_known: true, plugin_status: 'active', plugin_version: '7.9.1', page_cache_enabled: true,
    server_cache_state: 'configured', server_cache_reason: 'module_ready', server_cache_configured: true,
    redis_connection_state: 'not_checked', redis_object_cache_configured: true,
    redis_host: 'localhost', redis_port: 6379, redis_database: 0, ...overrides,
});
const verification = (state = 'hit', overrides = {}) => ({
    state, reason: state === 'hit' ? 'cache_hit_observed' : 'cache_miss_observed',
    checked_at: '2026-10-09T08:00:00Z', source: 'local_origin', url: 'https://example.com/',
    attempts: [{ status_code: 200, cache_header: state, cache_control: '', litespeed_cache_control: '', set_cookie: false, content_type: 'text/html' }],
    ...overrides,
});

function setup(overrides = {}) {
    const calls = [];
    const context = {
        t: key => key, showToast() {}, confirmModal: async () => true, currentLocale: () => 'zh-CN', URL,
        window: { location: { pathname: '/panel/websites/1', hash: '' } },
        api: async (url, options) => { calls.push({ url, options }); return { success: true, data: runtime() }; },
        ...overrides,
    };
    vm.createContext(context);
    vm.runInContext(source, context);
    const page = context.websiteDetail();
    page.site = { id: 1, site_type: 'wordpress', status: 'active', domain: 'example.com', ssl_enabled: true, litespeed_cache_enabled: false };
    page.refreshSiteSecurityAfterChange = () => {};
    const evaluate = expression => {
        const scope = Object.fromEntries(Object.entries(page).map(([key, value]) => [key, typeof value === 'function' ? value.bind(page) : value]));
        return vm.runInNewContext(expression, { ...context, ...scope });
    };
    const cardTexts = () => [evaluate(serverText), page.liteSpeedPluginStatusText(), evaluate(pageText), evaluate(redisText)];
    return { context, page, calls, evaluate, cardTexts };
}

test('initial module/plugin/page/Redis observations are unknown, with no endpoint or hit', () => {
    const { page, evaluate, cardTexts } = setup();
    assert.deepEqual(cardTexts(), ['cache_status.server_unknown', ...Array(3).fill('website.cache_status_unknown')]);
    assert.equal(evaluate(redisEndpoint[1]), false);
    assert.equal(page.cacheStatusFailed, false);
    assert.equal(evaluate(resultText), 'cache_status.result_not_verified');
    assert.equal(evaluate(resultClass), 'badge-info');
});

test('plugin settings and actual module configuration are separate from the removed DB switch', async () => {
    const { page, calls, cardTexts } = setup();
    await page.fetchLiteSpeedCacheStatus();
    assert.deepEqual(cardTexts(), ['cache_status.server_configured', 'website.litespeed_plugin_active', 'website.enabled', 'website.configured']);
    assert.equal(Object.hasOwn(page.cacheRuntime, 'server_page_cache_enabled'), false);
    assert.equal(calls[0].url, '/websites/1/litespeed-cache/status');
    assert.equal(calls[0].options.cache, 'no-store');
    assert.equal(page.cacheVerification, null, 'settings refresh must not claim a hit');
});

test('module configuration stays observable when plugin collection is unknown', async () => {
    const { page, cardTexts } = setup({ api: async () => ({ success: true, data: runtime({
        status_known: false, plugin_status: 'unknown', page_cache_enabled: false, redis_object_cache_configured: false,
    }) }) });
    await page.fetchLiteSpeedCacheStatus();
    assert.deepEqual(cardTexts(), ['cache_status.server_configured', ...Array(3).fill('website.cache_status_unknown')]);
});

test('each response replaces optional versions and endpoints', async () => {
    const { page, context } = setup();
    await page.fetchLiteSpeedCacheStatus();
    context.api = async () => ({ success: true, data: {
        status_known: true, plugin_status: 'inactive', page_cache_enabled: false, redis_object_cache_configured: false,
        server_cache_state: 'misconfigured', server_cache_reason: 'cache_module_missing', server_cache_configured: false,
    } });
    await page.fetchLiteSpeedCacheStatus();
    assert.equal(page.cacheRuntime.plugin_version, '');
    assert.equal(page.cacheRuntime.redis_host, '');
    assert.equal(page.cacheRuntime.redis_port, 0);
    assert.equal(page.cacheRuntime.server_cache_state, 'misconfigured');
});

test('network/bad-payload failures clear old runtime claims and permit retry', async () => {
    for (const reply of [null, { success: false }, { success: true }, { success: true, data: { status_known: true } }]) {
        const { page, context, cardTexts, evaluate } = setup();
        await page.fetchLiteSpeedCacheStatus();
        context.api = async () => { if (reply === null) throw new Error('timeout'); return reply; };
        await page.fetchLiteSpeedCacheStatus();
        assert.deepEqual(cardTexts(), Array(4).fill('website.cache_status_failed'));
        assert.equal(page.cacheRuntime.server_cache_configured, null);
        assert.equal(evaluate(redisEndpoint[1]), false);
        assert.equal(page.cacheStatusLoading, false);
        context.api = async () => ({ success: true, data: runtime() });
        await page.fetchLiteSpeedCacheStatus();
        assert.equal(page.cacheRuntime.server_cache_state, 'configured');
    }
});

test('duplicate refresh is guarded and a delayed old-site response is ignored', async () => {
    let finish;
    let requests = 0;
    const { page } = setup({ api: () => { requests++; return new Promise(resolve => { finish = resolve; }); } });
    const pending = page.fetchLiteSpeedCacheStatus();
    await page.fetchLiteSpeedCacheStatus();
    assert.equal(requests, 1);
    page.site = { ...page.site, id: 2 };
    finish({ success: true, data: runtime() });
    await pending;
    assert.equal(page.cacheRuntime.status_known, false);
    assert.equal(page.cacheStatusLoading, false);
});

test('WordPress saves omit the old public-cache flag, invalidate hit evidence and refresh real config', async () => {
    const { page, context, calls } = setup();
    page.lscacheEnabled = true;
    page.cacheVerification = verification();
    context.api = async (url, options) => {
        calls.push({ url, options });
        return { success: true, data: url.endsWith('/status') ? runtime({ page_cache_enabled: false }) : {} };
    };
    await page.saveWPOptimizations();
    assert.equal(Object.hasOwn(calls[0].options.body, 'litespeed_cache_enabled'), false);
    assert.equal(page.site.litespeed_cache_enabled, false);
    assert.equal(calls.at(-1).url, '/websites/1/litespeed-cache/status');
    assert.equal(page.cacheRuntime.server_cache_state, 'configured');
    assert.equal(page.cacheRuntime.page_cache_enabled, false);
    assert.equal(page.cacheVerification, null);
    assert.equal(page.optimizationSaving, false);
});

test('PHP retains its legacy field and never calls WordPress cache APIs', async () => {
    const { page, calls } = setup();
    page.site.site_type = 'php'; page.lscacheEnabled = true;
    await page.saveWPOptimizations();
    assert.equal(calls.length, 1);
    assert.equal(calls[0].options.body.litespeed_cache_enabled, true);
    await page.verifyPageCache(); page.site = null;
    await page.fetchLiteSpeedCacheStatus(); await page.verifyPageCache();
    assert.equal(calls.length, 1);
    assert.match(html, /x-show="site\.site_type === 'php'"[^>]*>[\s\S]*?x-model="lscacheEnabled"/);
});

test('Redis sockets do not invent port 6379 or claim connectivity', async () => {
    const { page, evaluate } = setup({ api: async () => ({ success: true, data: runtime({ redis_host: '/run/redis/redis.sock', redis_port: 0 }) }) });
    await page.fetchLiteSpeedCacheStatus();
    assert.equal(evaluate(redisEndpoint[1]), true);
    assert.equal(evaluate(redisEndpoint[2]), '/run/redis/redis.sock · DB 0');
    assert.match(partial, /cache_status\.redis_help/);
});

test('verification has a POST concurrency guard and clears a prior hit immediately', async () => {
    let finish; let requests = 0; let options;
    const { page, evaluate } = setup({ api: (_, supplied) => { requests++; options = supplied; return new Promise(resolve => { finish = resolve; }); } });
    page.cacheVerification = verification();
    const pending = page.verifyPageCache();
    assert.equal(page.cacheVerifying, true); assert.equal(page.cacheVerification, null);
    assert.equal(evaluate(resultClass), 'badge-info');
    await page.verifyPageCache(); assert.equal(requests, 1); assert.equal(options.method, 'POST');
    finish({ success: true, data: verification('miss') }); await pending;
    assert.equal(page.cacheVerification.state, 'miss'); assert.equal(evaluate(resultClass), 'badge-info');
    assert.equal(page.cacheVerifying, false);
});

test('unknown/bypass can never become a hit from old state or stray headers', async () => {
    for (const state of ['unknown', 'bypass']) {
        const { page, evaluate } = setup({ api: async () => ({ success: true, data: verification(state, {
            reason: 'cache_header_absent', attempts: [{ status_code: 200, cache_header: 'hit', set_cookie: false, content_type: 'text/html' }],
        }) }) });
        page.cacheVerification = verification(); await page.verifyPageCache();
        assert.equal(page.cacheVerification.state, state); assert.equal(evaluate(resultClass), 'badge-info');
    }
});

test('invalid/error verification cannot fabricate a green hit', async () => {
    for (const reply of [
        { success: false }, { success: true }, { success: true, data: { state: 'hit' } },
        { success: true, data: verification('hit', { attempts: [] }) },
        { success: true, data: verification('hit', { url: 'https://other.example.com/' }) },
        { success: true, data: verification('hit', { url: 'https://example.com/wp-admin/' }) },
        { success: true, data: verification('hit', { checked_at: 'invalid' }) },
        { success: true, data: verification('hit', { attempts: [{ status_code: 200, cache_header: 'hit', set_cookie: true }] }) },
    ]) {
        const { page, evaluate } = setup({ api: async () => reply });
        page.cacheVerification = verification(); await page.verifyPageCache();
        assert.equal(page.cacheVerification, null, JSON.stringify(reply)); assert.ok(page.cacheVerificationError);
        assert.equal(evaluate(resultClass), 'badge-info'); assert.equal(page.cacheVerifying, false);
    }
    const { page, evaluate } = setup({ api: async () => { throw new Error('timeout'); } });
    page.cacheVerification = verification(); await page.verifyPageCache();
    assert.equal(page.cacheVerification, null); assert.equal(page.cacheVerificationError, 'timeout');
    assert.equal(evaluate(resultClass), 'badge-info');
});

test('a verified hit retains response evidence and a localized timestamp', async () => {
    const { page, evaluate } = setup({ api: async () => ({ success: true, data: verification() }) });
    await page.verifyPageCache(); assert.equal(page.cacheVerification.state, 'hit');
    assert.equal(evaluate(resultClass), 'badge-success'); assert.equal(page.cacheCheckedAt().includes('2026'), true);
    page.cacheVerification.checked_at = 'invalid'; assert.equal(page.cacheCheckedAt(), '—');
});

test('delayed verification cannot attach the previous site hit to a new site', async () => {
    let finish;
    const { page, evaluate } = setup({ api: () => new Promise(resolve => { finish = resolve; }) });
    const pending = page.verifyPageCache(); page.site = { ...page.site, id: 2 };
    finish({ success: true, data: verification() }); await pending;
    assert.equal(page.cacheVerification, null); assert.equal(evaluate(resultClass), 'badge-info');
});

test('inactive websites never issue cache verification requests', async () => {
    const { page, calls } = setup(); page.site.status = 'paused';
    await page.verifyPageCache(); assert.equal(calls.length, 0);
});

test('an origin preflight failure without a request URL retains its reason instead of becoming a payload error', async () => {
    const { page, evaluate } = setup({ api: async () => ({ success: true, data: verification('unknown', {
        url: '', reason: 'cache_module_missing', attempts: [],
    }) }) });
    await page.verifyPageCache();
    assert.equal(page.cacheVerification.state, 'unknown');
    assert.equal(page.cacheVerification.reason, 'cache_module_missing');
    assert.equal(page.cacheVerificationError, '');
    assert.equal(evaluate(resultClass), 'badge-info');
});
