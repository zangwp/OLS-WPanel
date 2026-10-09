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
    assert.match(html, /<div x-data="websiteDetail\(\)"[^>]*>/);
    assert(!/<div x-data="websiteDetail\(\)"[^>]*x-init=/.test(html));
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

test('leaving security for logs cancels a real API maintenance read without a browser abort toast', async () => {
    const {page, context, notices, response} = setup({hash:'#site-security'});
    const app = fs.readFileSync(path.join(__dirname, '../../web/js/app.js'), 'utf8');
    const requests = [];
    Object.assign(context, {
        FormData, setTimeout, clearTimeout, console:{error() {}},
        document:{hidden:false, body:{dataset:{panelPrefix:'/panel'}}, querySelector:() => null},
        fetch:async (url, options) => {
            const route = url.replace('/panel/api', ''); requests.push({route, options});
            if (route.endsWith('/maintenance')) return new Promise((_resolve, reject) => options.signal.addEventListener('abort', () => reject(new DOMException('signal is aborted without reason', 'AbortError')), {once:true}));
            return {status:200, ok:true, headers:{get:() => 'application/json'}, json:async () => response(route)};
        },
    });
    vm.runInContext(app.slice(app.indexOf('function api('), app.indexOf('const __apiGetCache')) + app.slice(app.indexOf('function friendlyAPIError('), app.indexOf('function formatBytes(')), context);
    page.init(); await settle();
    assert.equal(page.maintenanceLoading, true);
    page.setDetailTab('logs'); await settle();
    assert.equal(requests.find(request => request.route.endsWith('/maintenance')).options.signal.aborted, true);
    assert.equal(page.detailTab, 'logs'); assert.equal(page.logContent, 'fixture log');
    assert.equal(page.logsLoaded, true); assert.equal(page.maintenanceLoading, false); assert.deepEqual(notices, []);
});

test('rapid log type switching aborts both old reads and late results cannot hide new loading or overwrite content', async () => {
    const {page, context, calls, notices} = setup(), pending = [];
    page.site = site(); page.detailTab = 'logs'; page.logFullscreen = true;
    context.api = (url, options) => { const request = deferred(); calls.push({url, options}); pending.push(request); return request.promise; };
    const first = page.loadLogs(); page.selectLogType('error');
    assert.equal(calls.length, 4); assert.equal(calls[0].options.signal.aborted, true); assert.equal(calls[1].options.signal.aborted, true);
    assert.equal(page.logFullscreen, true, 'switching type in fullscreen must keep the log viewer open');
    pending[0].resolve({success:true, data:{content:'old access'}}); pending[1].resolve({success:true, data:{files:[{name:'old-access.log'}]}});
    await first; assert.equal(page.logContent, ''); assert.equal(page.logFiles.length, 0); assert.equal(page.logsLoading, true); assert.equal(page.logsLoaded, false);
    pending[2].resolve({success:true, data:{content:'current error'}}); pending[3].resolve({success:true, data:{files:[{name:'error.log'}]}}); await settle();
    assert.equal(page.logContent, 'current error'); assert.equal(page.logFiles[0].name, 'error.log');
    assert.equal(page.logsLoaded, true); assert.equal(page.logsLoading, false); assert.deepEqual(notices, []);
    for (const call of calls) { assert.equal(call.options.silent, true); assert.equal(call.options.timeout, 20000); assert.equal(call.options.cache, 'no-store'); }
});

test('changing the log line limit replaces the pending preview and only the newest result may update it', async () => {
    const {page, context, calls, notices} = setup(), pending = [];
    page.site = site(); page.detailTab = 'logs';
    context.api = (url, options) => { const request = deferred(); calls.push({url, options}); pending.push(request); return request.promise; };
    const first = page.fetchLogs(); page.logLineLimit = 1000; const second = page.fetchLogs();
    assert.equal(calls[0].options.signal.aborted, true); assert.match(calls[1].url, /lines=1000$/);
    pending[0].reject(new DOMException('signal is aborted without reason', 'AbortError')); await first;
    assert.equal(page.logContentLoading, true); assert.equal(page.logContentError, '');
    pending[1].resolve({success:true, data:{content:'new 1000-line preview'}}); await second;
    assert.equal(page.logContent, 'new 1000-line preview'); assert.equal(page.logContentLoading, false); assert.deepEqual(notices, []);
});

test('leaving logs cancels reads, rejects late content and returning starts fresh requests', async () => {
    const {page, context, calls, response, notices} = setup(), pending = [];
    page.site = site(); page.detailTab = 'logs';
    context.api = (url, options) => {
        calls.push({url, options});
        if (!url.includes('/logs?') && !url.includes('/log-files?')) return Promise.resolve(response(url));
        const request = deferred(); pending.push(request); return request.promise;
    };
    const first = page.loadLogs(); page.setDetailTab('overview');
    assert.equal(calls[0].options.signal.aborted, true); assert.equal(calls[1].options.signal.aborted, true); assert.equal(page.logsLoading, false);
    pending[0].resolve({success:true, data:{content:'hidden late preview'}}); pending[1].resolve({success:true, data:{files:[{name:'late.log'}]}}); await first;
    assert.equal(page.logContent, ''); assert.equal(page.logFiles.length, 0); assert.equal(page.logsLoaded, false);
    page.setDetailTab('logs'); assert.equal(pending.length, 4); assert.equal(page.logsLoading, true);
    page.destroy(); pending[2].resolve({success:true, data:{content:'destroyed preview'}}); pending[3].resolve({success:true, data:{files:[]}}); await settle();
    assert.equal(page.logContent, ''); assert.equal(page.logsLoaded, false); assert.equal(page.logsLoading, false); assert.deepEqual(notices, []);
});

test('a real log read failure shows one error and remains retryable instead of marking the tab loaded', async () => {
    const {page, context, calls, response, notices} = setup(); page.site = site(); page.detailTab = 'logs';
    context.api = async (url, options) => { calls.push({url, options}); if (url.includes('/logs?')) throw new Error('offline'); return response(url); };
    await page.loadLogs();
    assert.equal(page.logsLoaded, false); assert.equal(page.logsLoading, false); assert.equal(page.logContentLoaded, false); assert.equal(page.logFilesLoaded, true);
    assert.equal(page.logContentError, 'website.load_logs_failed'); assert.deepEqual(notices, [['website.load_logs_failed','error']]);
    context.api = async (url, options) => { calls.push({url, options}); return response(url); };
    await page.loadLogs(); assert.equal(page.logsLoaded, true); assert.equal(page.logContentError, ''); assert.equal(page.logContent, 'fixture log');
});

test('a response from a previous site cannot update the current site log content or list', async () => {
    const {page, context, notices} = setup(), pending = []; page.site = site(); page.detailTab = 'logs';
    context.api = () => { const request = deferred(); pending.push(request); return request.promise; };
    const first = page.loadLogs(); page.site = {...site(), id:2};
    pending[0].resolve({success:true, data:{content:'another site log'}}); pending[1].reject(new Error('another site error')); await first;
    assert.equal(page.logContent, ''); assert.equal(page.logFiles.length, 0); assert.equal(page.logsLoaded, false); assert.equal(page.logsLoading, false); assert.deepEqual(notices, []);
});

test('invalid log payloads are failures rather than successfully loaded blank views', async () => {
    const {page, context, notices} = setup(); page.site = site(); page.detailTab = 'logs';
    context.api = async () => ({success:true, data:{}});
    await page.loadLogs(); assert.equal(page.logsLoaded, false); assert.equal(page.logsLoading, false);
    assert.equal(page.logContentError, 'website.load_logs_failed'); assert.equal(page.logFilesError, 'website.load_log_files_failed'); assert.equal(notices.length, 2);
});

test('a real API log timeout is localized and emitted once by the log view', async () => {
    const {page, context, notices, response} = setup(); page.site = site(); page.detailTab = 'logs';
    const app = fs.readFileSync(path.join(__dirname, '../../web/js/app.js'), 'utf8'), timers = new Map(); let timerID = 0;
    Object.assign(context, {
        FormData, console:{error() {}}, t:(key, params = {}) => params.error ? key + ': ' + params.error : key,
        document:{hidden:false, body:{dataset:{panelPrefix:'/panel'}}, querySelector:() => null},
        setTimeout(callback) { const id = ++timerID; timers.set(id, callback); return id; }, clearTimeout:id => timers.delete(id),
        fetch:async (url, options) => {
            const route = url.replace('/panel/api', '');
            if (route.includes('/logs?')) return new Promise((_resolve, reject) => options.signal.addEventListener('abort', () => reject(options.signal.reason), {once:true}));
            return {status:200, ok:true, headers:{get:() => 'application/json'}, json:async () => response(route)};
        },
    });
    vm.runInContext(app.slice(app.indexOf('function api('), app.indexOf('const __apiGetCache')) + app.slice(app.indexOf('function friendlyAPIError('), app.indexOf('function formatBytes(')), context);
    const pending = page.loadLogs(); await settle(); [...timers.values()][0](); await pending;
    assert.equal(page.logsLoaded, false); assert.equal(page.logsLoading, false); assert.equal(timers.size, 0);
    assert.equal(page.logContentError, 'website.load_logs_failed: common.request_timeout');
    assert.deepEqual(notices, [['website.load_logs_failed: common.request_timeout','error']]);
});

test('clear confirmation is tied to the displayed log type and cannot clear a new selection', async () => {
    const {page, context, calls, response, notices} = setup(), confirm = deferred(); page.site = site(); page.detailTab = 'logs';
    context.confirmModal = () => confirm.promise;
    context.api = async (url, options) => { calls.push({url, options}); return response(url); };
    const clearing = page.clearLogs(); page.selectLogType('error'); confirm.resolve(true); await clearing; await settle();
    assert.equal(calls.some(call => call.options?.method === 'DELETE'), false); assert.equal(page.logClearing, false); assert.deepEqual(notices, []);
});

test('a completed clear cancels pre-delete reads so late preview data cannot restore deleted content', async () => {
    const {page, context, calls, response} = setup(), preview = deferred(), deletion = deferred(); page.site = site(); page.detailTab = 'logs';
    context.confirmModal = async () => true;
    context.api = (url, options) => {
        calls.push({url, options});
        if (options?.method === 'DELETE') return deletion.promise;
        if (url.includes('/logs?')) return preview.promise;
        return Promise.resolve(response(url));
    };
    const pending = page.fetchLogs(), clearing = page.clearLogs(); await settle();
    assert.equal(calls[0].options.signal.aborted, true); const mutation = calls.find(call => call.options.method === 'DELETE');
    assert.equal(mutation.url, '/websites/1/logs?type=access'); assert.equal(mutation.options.silent, true);
    deletion.resolve({success:true, data:{}}); await clearing; preview.resolve({success:true, data:{content:'deleted late content'}}); await pending; await settle();
    assert.equal(page.logContent, 'website.log_empty_or_missing'); assert.equal(page.logContentLoaded, true); assert.equal(page.logsLoaded, true); assert.equal(page.logClearing, false);
});

test('a late clear completion cannot blank a newer visit to the same log type', async () => {
    const {page, context, calls, response, notices} = setup(), deletion = deferred(); page.site = site(); page.detailTab = 'logs';
    context.confirmModal = async () => true;
    context.api = (url, options) => { calls.push({url, options}); return options?.method === 'DELETE' ? deletion.promise : Promise.resolve(response(url)); };
    const clearing = page.clearLogs(); await settle(); page.selectLogType('error'); await settle(); page.selectLogType('access'); await settle();
    assert.equal(page.logContent, 'fixture log'); deletion.resolve({success:true, data:{}}); await clearing;
    assert.equal(page.logContent, 'fixture log'); assert.equal(page.logsLoaded, true); assert.equal(page.logClearing, false); assert.deepEqual(notices, []);
});

test('basic administrator access opens the detected same-site login or installation URL in a protected new tab', () => {
    const {page, calls}=setup();page.site=site();assert.equal(page.wordpressAdminURL(),'');
    const link=html.match(/<a[^>]*:href="wordpressAdminURL\(\)[^>]*>/)[0];assert.match(link,/target="_blank"/);assert.match(link,/rel="noopener noreferrer"/);assert(!link.includes('scrollIntoView'));
    for(const login of ['https://site.example/wp-login.php','https://site.example/custom-login/','https://site.example/plugin-login/']){
        page.acceptWordPressAccessStatus({site_id:1,installed:true,login_url:login});assert.equal(page.wordpressAdminURL(),login);
    }
    page.acceptWordPressAccessStatus({site_id:1,installed:false,install_url:'https://site.example/wp-admin/install.php'});assert.equal(page.wordpressAdminURL(),'https://site.example/wp-admin/install.php');assert.equal(calls.length,0);
});

test('administrator address events reject foreign, mixed-content and malformed destinations', () => {
    const {page}=setup();page.site=site();
    for(const login of ['javascript:alert(1)','https://other.example/login/','http://site.example/login/','https://admin@site.example/','https://site.example/#proof','https://site.example/'+ 'a'.repeat(2048)]){
        page.acceptWordPressAccessStatus({site_id:1,installed:true,login_url:'https://site.example/native/'});
        page.acceptWordPressAccessStatus({site_id:1,installed:true,login_url:login});assert.equal(page.wordpressAdminURL(),'');
    }
    page.acceptWordPressAccessStatus({site_id:1,installed:true,login_url:'https://site.example/native/'});
    page.acceptWordPressAccessStatus({site_id:2,installed:true,login_url:'https://other.example/'});assert.equal(page.wordpressAdminURL(),'https://site.example/native/');
    page.acceptWordPressAccessStatus({site_id:1,installed:undefined});assert.equal(page.wordpressAdminURL(),'');
    page.site.site_type='php';page.acceptWordPressAccessStatus({site_id:1,installed:true,login_url:'https://site.example/login/'});assert.equal(page.wordpressAdminURL(),'');
});
