const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const {test} = require('node:test');

const html = fs.readFileSync(path.join(__dirname, '../../web/templates/website_detail.html'), 'utf8');
const source = [...html.matchAll(/<script[^>]*>([\s\S]*?)<\/script>/g)].map(match => match[1].replace(/{{[\s\S]*?}}/g, 'translated')).join('\n');
const deferred = () => { let resolve, reject; const promise = new Promise((a, b) => { resolve = a; reject = b; }); return {promise, resolve, reject}; };
const settle = async () => { for (let i = 0; i < 4; i++) await new Promise(resolve => setImmediate(resolve)); };
const site = (type = 'wordpress') => ({id:1, domain:'site.example', site_type:type, status:'active', ssl_enabled:true, litespeed_cache_enabled:false, litespeed_cache_ttl:300, disable_wp_updates:false, disable_file_editing:true, xmlrpc_enabled:false, disable_application_passwords:true, wp_debug_enabled:false, wp_debug_display:false, wp_post_revisions:-1, wp_memory_limit:'', file_lock_enabled:false});
function setup({hash = '', type = 'wordpress'} = {}) {
    const calls = [], notices = [], listeners = new Map(), removed = [], intervals = new Map(), cleared = [];
    let timerID = 0;
    const response = url => {
        let data;
        if (url === '/websites/1') data = site(type);
        else if (url.endsWith('/security-status')) data = {site_id:1, checks:[], checked_at:'2026-10-09T08:00:00Z'};
        else if (url === '/cron' || url === '/software/php-runtimes') data = [];
        else if (url.endsWith('/maintenance')) data = {state:'locked', enabled:true, minutes:5};
        else if (url.endsWith('/maintenance/password')) data = {password:'maintenance-fixture'};
        else if (url.endsWith('/ai-development-access')) data = {status:'disabled', tools:[]};
        else if (url.endsWith('/install-plugin/status')) data = {status:'installed'};
        else if (url.endsWith('/litespeed-cache/status')) data = {status_known:true, plugin_status:'active', server_cache_state:'configured'};
        else if (url.includes('/log-files?')) data = {files:[]};
        else if (url.includes('/logs?')) data = {content:'fixture log'};
        else if (url.endsWith('/ssl/renewal')) data = {enabled:true};
        else throw new Error('Unexpected API fixture: ' + url);
        return {success:true, data};
    };
    const context = {
        URL, AbortController, t:key => key, currentLocale:() => 'en-US', showToast:(...args) => notices.push(args), document:{hidden:false},
        window:{location:{pathname:'/panel/websites/1', search:'?lang=en-US', hash}, history:{replaceState(_state, _title, url) { context.window.location.hash = url.slice(url.indexOf('#')); }},
            addEventListener(name, callback) { assert(!listeners.has(name), 'duplicate ' + name + ' listener'); listeners.set(name, callback); },
            removeEventListener(name, callback) { removed.push({name, callback}); if (listeners.get(name) === callback) listeners.delete(name); }},
        setInterval(callback, delay) { const id = ++timerID; intervals.set(id, {callback, delay}); return id; },
        clearInterval(id) { cleared.push(id); intervals.delete(id); },
        api:async(url, options) => { calls.push({url, options}); return response(url); },
    };
    vm.createContext(context); vm.runInContext(source, context);
    return {page:context.websiteDetail(), context, calls, notices, listeners, removed, intervals, cleared, response};
}
const paths = calls => calls.map(call => call.url);
const overviewPaths = ['/websites/1/ssl/renewal', '/websites/1/ai-development-access', '/software/php-runtimes'];
const cachePaths = ['/websites/1/install-plugin/status', '/websites/1/litespeed-cache/status'];
const securityPaths = ['/websites/1/security-status', '/cron', '/websites/1/maintenance', '/websites/1/maintenance/password'];
const logPaths = ['/websites/1/logs?type=access&lines=200', '/websites/1/log-files?type=access'];

test('website details have one initialization hook and repeated init does not duplicate reads or listeners', async () => {
    assert.match(html, /<div x-data="websiteDetail\(\)">/);
    const {page, calls, listeners} = setup(); page.init(); page.init(); await settle();
    assert.deepEqual(paths(calls).sort(), ['/websites/1', ...overviewPaths].sort());
    assert.equal(listeners.size, 1); assert.equal(page.loading, false); assert.equal(page.detailLoading, false);
});

for (const [hash, tab, expected] of [['#cache-performance','cache',cachePaths], ['#site-security','security',securityPaths], ['#site-logs','logs',logPaths]]) {
    test('first load honors ' + hash + ' and avoids requests for hidden tabs', async () => {
        const {page, calls, intervals} = setup({hash}); page.init(); await settle();
        assert.equal(page.detailTab, tab); assert.deepEqual(paths(calls).sort(), ['/websites/1', ...expected].sort());
        assert.equal(intervals.size, tab === 'security' ? 1 : 0);
    });
}

test('PHP security does not read WordPress jobs, credentials or maintenance state', async () => {
    const {page, calls, intervals} = setup({hash:'#site-security', type:'php'}); page.init(); await settle();
    assert.deepEqual(paths(calls), ['/websites/1', '/websites/1/security-status']); assert.equal(intervals.size, 0);
});

test('hash navigation loads its target once and a loaded overview can be revisited without duplicate reads', async () => {
    const {page, context, calls, listeners} = setup(); page.init(); await settle();
    context.window.location.hash = '#logs'; listeners.get('hashchange')(); await settle();
    assert.equal(page.detailTab, 'logs'); assert.deepEqual(paths(calls).slice(4).sort(), logPaths.slice().sort());
    page.setDetailTab('overview'); await settle(); assert.equal(calls.length, 6);
    assert.equal(context.window.location.hash, '#overview');
});

test('overlapping tab loads share a loading guard', async () => {
    const {page, context, calls, response} = setup(); const pending = deferred(); page.site = site(); page.detailTab = 'cache';
    context.api = async (url, options) => { calls.push({url, options}); return url.endsWith('/install-plugin/status') ? pending.promise : response(url); };
    const first = page.loadDetailTab('cache'); await page.loadDetailTab('cache');
    assert.deepEqual(paths(calls), [cachePaths[0]]);
    pending.resolve(response(cachePaths[0])); await first;
    assert.deepEqual(paths(calls), cachePaths); assert.equal(page.tabLoads.cache.loading, false);
});

test('interrupted cache load remains incomplete and returning to cache loads its runtime status', async () => {
    const {page, context, calls, response} = setup(); const pending = deferred(); page.site = site(); page.detailTab = 'cache';
    context.api = async (url, options) => { calls.push({url, options}); return url.endsWith('/install-plugin/status') ? pending.promise : response(url); };
    const first = page.loadDetailTab('cache'); page.setDetailTab('logs'); pending.resolve(response(cachePaths[0])); await first; await settle();
    assert.equal(paths(calls).includes(cachePaths[1]), false); assert.equal(page.tabLoads.cache.loaded, false);
    page.setDetailTab('cache'); await settle();
    assert.equal(paths(calls).filter(url => url === cachePaths[1]).length, 1); assert.equal(page.tabLoads.cache.loaded, true);
});

test('failed initial details remain visible as an error and an explicit retry loads the page', async () => {
    const {page, context, calls, response} = setup(); context.api = async (url, options) => { calls.push({url, options}); throw new Error('offline'); };
    page.init(); await settle(); assert.equal(page.site, null); assert(page.siteLoadError); assert.equal(page.loading, false);
    assert.match(html, /x-show="siteLoadError"[\s\S]*?role="alert"/); assert.match(html, /@click="fetchDetail\(\)"/);
    context.api = async (url, options) => { calls.push({url, options}); return response(url); };
    await page.fetchDetail(); await settle(); assert.equal(page.siteLoadError, ''); assert.equal(page.site.id, 1); assert.equal(page.loading, false);
});

test('destroy removes the hash listener and prevents a pending initial read from rebuilding the page', async () => {
    const {page, context, calls, listeners, removed, response} = setup(); const pending = deferred(); context.api = async (url, options) => { calls.push({url, options}); return pending.promise; };
    page.init(); page.destroy(); pending.resolve(response('/websites/1')); await settle();
    assert.equal(page.site, null); assert.equal(calls.length, 1); assert.equal(listeners.size, 0); assert.equal(removed[0].name, 'hashchange');
    await page.fetchDetail(); await page.loadDetailTab('security'); assert.equal(calls.length, 1);
});

test('leaving security stops polling, clears credentials and returning refreshes maintenance once', async () => {
    const {page, calls, intervals, cleared} = setup({hash:'#site-security'}); page.init(); await settle();
    assert.equal(page.maintenancePasswordInput, 'maintenance-fixture'); assert.equal(intervals.size, 1);
    page.setDetailTab('logs'); await settle(); assert.equal(intervals.size, 0); assert.equal(cleared.length, 1); assert.equal(page.maintenancePasswordInput, '');
    page.setDetailTab('security'); await settle(); assert.equal(intervals.size, 1); assert.equal(page.maintenancePasswordInput, 'maintenance-fixture');
    assert.equal(paths(calls).filter(url => url.endsWith('/maintenance/password')).length, 2);
    page.destroy(); assert.equal(intervals.size, 0); assert.equal(page.maintenancePasswordInput, '');
});

test('maintenance polling skips hidden, saving and inactive tabs', async () => {
    const {page, context, calls, intervals} = setup({hash:'#site-security'}); page.init(); await settle();
    const poll = [...intervals.values()][0]; assert.equal(poll.delay, 10000); const before = calls.length;
    context.document.hidden = true; poll.callback(); context.document.hidden = false; page.maintenanceSaving = true; poll.callback();
    page.maintenanceSaving = false; page.detailTab = 'logs'; poll.callback(); assert.equal(calls.length, before);
    page.detailTab = 'security'; poll.callback(); await settle(); assert.equal(calls.length, before + 1);
});

test('a delayed maintenance password cannot restore its secret after leaving security', async () => {
    const {page, context, calls, response} = setup({hash:'#site-security'}); const pending = deferred();
    context.api = async (url, options) => { calls.push({url, options}); return url.endsWith('/maintenance/password') ? pending.promise : response(url); };
    page.init(); await settle(); assert(paths(calls).includes('/websites/1/maintenance/password'));
    page.setDetailTab('logs'); pending.resolve({success:true, data:{password:'late-secret'}}); await settle();
    assert.equal(page.maintenancePasswordInput, '');
});
