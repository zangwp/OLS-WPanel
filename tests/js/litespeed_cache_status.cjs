const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const { test } = require('node:test');

const html = fs.readFileSync(path.join(__dirname, '../../web/templates/website_detail.html'), 'utf8');
const source = [...html.matchAll(/<script[^>]*>([\s\S]*?)<\/script>/g)]
    .map(match => match[1].replace(/{{[\s\S]*?}}/g, 'translated')).join('\n');
const texts = [...html.matchAll(/<p\b[^>]*\bx-text="([^"]*)"/g)].map(match => match[1]);
const pageText = texts.find(expression => expression.includes('cacheRuntime.page_cache_enabled'));
const redisText = texts.find(expression => expression.includes('cacheRuntime.redis_object_cache_configured') && expression.includes('cache_status'));
const redisEndpoint = [...html.matchAll(/<p\b[^>]*\bx-show="([^"]*)"[^>]*\bx-text="([^"]*)"/g)]
    .find(match => match[2] === 'redisCacheEndpointText()');

const runtime = (overrides = {}) => ({
    status_known: true, plugin_status: 'active', plugin_version: '7.9.1',
    page_cache_enabled: true, server_page_cache_enabled: false,
    redis_object_cache_configured: true, redis_host: 'localhost', redis_port: 6379, redis_database: 0,
    ...overrides,
});

function setup(overrides = {}) {
    const calls = [];
    const context = {
        t: key => key, showToast() {}, confirmModal: async () => true,
        window: { location: { pathname: '/panel/websites/1', hash: '' } },
        api: async (url, options) => { calls.push({ url, options }); return { success: true, data: runtime() }; },
        ...overrides,
    };
    vm.createContext(context);
    vm.runInContext(source, context);
    const page = context.websiteDetail();
    page.site = { id: 1, site_type: 'wordpress', litespeed_cache_enabled: false };
    const evaluate = expression => {
        const scope = Object.fromEntries(Object.entries(page).map(([key, value]) => [key, typeof value === 'function' ? value.bind(page) : value]));
        return vm.runInNewContext(expression, { ...context, ...scope });
    };
    const cardTexts = () => [page.liteSpeedPluginStatusText(), evaluate(pageText), evaluate(redisText)];
    return { context, page, calls, evaluate, cardTexts };
}

test('initial runtime is unknown rather than disabled, with no Redis endpoint', () => {
    const { page, evaluate, cardTexts } = setup();
    assert.deepEqual(cardTexts(), Array(3).fill('website.cache_status_unknown'));
    assert.equal(evaluate(redisEndpoint[1]), false);
    assert.equal(page.cacheStatusFailed, false);
});

test('WordPress ON settings are displayed even when the server cache is off', async () => {
    const { page, calls, cardTexts } = setup();
    await page.fetchLiteSpeedCacheStatus();
    assert.deepEqual(cardTexts(), ['website.litespeed_plugin_active', 'website.enabled', 'website.configured']);
    assert.equal(page.cacheRuntime.server_page_cache_enabled, false);
    assert.equal(page.lscacheEnabled, false, 'a status refresh must not change the saved server setting');
    assert.equal(calls[0].url, '/websites/1/litespeed-cache/status');
    assert.equal(calls[0].options.cache, 'no-store');
    assert.equal(calls[0].options.timeout, 30000);
});

test('a plugin cache OFF setting does not disable the server setting during save', async () => {
    const { page, context, calls } = setup();
    page.lscacheEnabled = true;
    context.api = async (url, options) => {
        calls.push({ url, options });
        return { success: true, data: url.endsWith('/status') ? runtime({ page_cache_enabled: false, server_page_cache_enabled: true }) : {} };
    };
    await page.fetchLiteSpeedCacheStatus();
    await page.saveWPOptimizations();
    const saved = calls.find(call => call.url.endsWith('/wp-optimizations'));
    assert.equal(page.cacheRuntime.page_cache_enabled, false);
    assert.equal(saved.options.body.litespeed_cache_enabled, true);
});

test('each response replaces optional fields instead of retaining stale versions or endpoints', async () => {
    const { page, context } = setup();
    await page.fetchLiteSpeedCacheStatus();
    context.api = async () => ({ success: true, data: {
        status_known: true, plugin_status: 'inactive', page_cache_enabled: false,
        server_page_cache_enabled: false, redis_object_cache_configured: false,
    } });
    await page.fetchLiteSpeedCacheStatus();
    assert.equal(page.cacheRuntime.plugin_version, '');
    assert.equal(page.cacheRuntime.redis_host, '');
    assert.equal(page.cacheRuntime.redis_port, 0);
    assert.equal(page.cacheStatusFailed, false);
});

test('a failed refresh clears prior runtime claims in all three cards and permits retry', async () => {
    const { page, context, cardTexts, evaluate } = setup();
    await page.fetchLiteSpeedCacheStatus();
    context.api = async () => { throw new Error('request timed out'); };
    await page.fetchLiteSpeedCacheStatus();
    assert.deepEqual(cardTexts(), Array(3).fill('website.cache_status_failed'));
    assert.equal(page.cacheRuntime.status_known, false);
    assert.equal(page.cacheRuntime.plugin_version, '');
    assert.equal(page.cacheRuntime.redis_host, '');
    assert.equal(evaluate(redisEndpoint[1]), false);
    assert.equal(page.cacheStatusLoading, false);
    context.api = async () => ({ success: true, data: runtime() });
    await page.fetchLiteSpeedCacheStatus();
    assert.equal(page.cacheStatusFailed, false);
    assert.deepEqual(cardTexts(), ['website.litespeed_plugin_active', 'website.enabled', 'website.configured']);
});

test('an incomplete backend observation is not shown as disabled or configured', async () => {
    const { page, context, cardTexts, evaluate } = setup();
    context.api = async () => ({ success: true, data: runtime({ status_known: false }) });
    await page.fetchLiteSpeedCacheStatus();
    assert.deepEqual(cardTexts(), Array(3).fill('website.cache_status_failed'));
    assert.equal(evaluate(redisEndpoint[1]), false);
});

test('unsuccessful or missing response data clears previously observed states', async () => {
    for (const reply of [{ success: false }, { success: true }, { success: true, data: null }]) {
        const { page, context, cardTexts } = setup();
        await page.fetchLiteSpeedCacheStatus();
        context.api = async () => reply;
        await page.fetchLiteSpeedCacheStatus();
        assert.deepEqual(cardTexts(), Array(3).fill('website.cache_status_failed'));
        assert.equal(page.cacheStatusLoading, false);
    }
});

test('refresh leaves an unsaved server checkbox change intact', async () => {
    const { page } = setup();
    page.lscacheEnabled = true;
    await page.fetchLiteSpeedCacheStatus();
    assert.equal(page.lscacheEnabled, true);
    assert.equal(page.cacheRuntime.server_page_cache_enabled, false);
});

test('duplicate refresh clicks share the in-progress guard', async () => {
    let finish;
    let requests = 0;
    const { page } = setup({ api: () => { requests++; return new Promise(resolve => { finish = resolve; }); } });
    const pending = page.fetchLiteSpeedCacheStatus();
    assert.equal(page.cacheStatusLoading, true);
    await page.fetchLiteSpeedCacheStatus();
    assert.equal(requests, 1);
    finish({ success: true, data: runtime() });
    await pending;
    assert.equal(page.cacheStatusLoading, false);
});

test('PHP sites and missing sites never request WordPress cache status', async () => {
    const { page, calls } = setup();
    page.site.site_type = 'php';
    await page.fetchLiteSpeedCacheStatus();
    page.site = null;
    await page.fetchLiteSpeedCacheStatus();
    assert.equal(calls.length, 0);
});

test('saving the independent server switch updates the server state without changing plugin policy', async () => {
    const { page, context, calls } = setup();
    await page.fetchLiteSpeedCacheStatus();
    page.lscacheEnabled = true;
    context.api = async (url, options) => { calls.push({ url, options }); return { success: true, data: {} }; };
    await page.saveWPOptimizations();
    assert.equal(calls.at(-1).options.body.litespeed_cache_enabled, true);
    assert.equal(page.site.litespeed_cache_enabled, true);
    assert.equal(page.cacheRuntime.server_page_cache_enabled, true);
    assert.equal(page.cacheRuntime.page_cache_enabled, true);
    assert.equal(page.cacheRuntime.redis_object_cache_configured, true);
});

test('a failed server save retains the last observed server state', async () => {
    const { page, context } = setup();
    await page.fetchLiteSpeedCacheStatus();
    page.lscacheEnabled = true;
    context.api = async () => { throw new Error('server reload failed'); };
    await page.saveWPOptimizations();
    assert.equal(page.cacheRuntime.server_page_cache_enabled, false);
    assert.equal(page.site.litespeed_cache_enabled, false);
    assert.equal(page.optimizationSaving, false);
});

test('a Redis Unix socket displays the real path without inventing TCP port 6379', async () => {
    const { page, evaluate } = setup({ api: async () => ({ success: true, data: runtime({
        redis_host: '/run/redis/redis.sock', redis_port: 0, redis_database: 0,
    }) }) });
    await page.fetchLiteSpeedCacheStatus();
    assert.equal(evaluate(redisEndpoint[1]), true);
    assert.equal(evaluate(redisEndpoint[2]), '/run/redis/redis.sock · DB 0');
});

test('migrating plugin ownership cannot change the independent server switch or TTL draft', async () => {
    for (const draft of [false, true]) {
        const { page, context, calls } = setup();
        page.lscacheEnabled = draft;
        page.lscacheTTL = 900;
        context.api = async (url, options) => {
            calls.push({ url, options });
            return { success: true, data: url.endsWith('/migrate') ? { migrated: true } : runtime() };
        };
        await page.applyRecommendedLiteSpeedCache();
        assert.equal(calls[0].url, '/websites/1/litespeed-cache/migrate');
        assert.equal(calls[0].options.method, 'POST');
        assert.equal(calls[1].url, '/websites/1/litespeed-cache/status');
        assert.equal(page.lscacheEnabled, draft);
        assert.equal(page.lscacheTTL, 900);
        assert.equal(page.site.litespeed_cache_enabled, false);
        assert.equal(page.cacheRuntime.server_page_cache_enabled, false);
        assert.equal(page.cacheApplying, false);
    }
});
