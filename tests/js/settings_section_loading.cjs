const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const {test} = require('node:test');

const html = fs.readFileSync(path.join(__dirname, '../../web/templates/settings.html'), 'utf8');
const source = [...html.matchAll(/<script[^>]*>([\s\S]*?)<\/script>/g)].map(m => m[1].replace(/{{[\s\S]*?}}/g, 'translated')).join('\n');
const settle = async () => { for (let i = 0; i < 4; i++) await new Promise(resolve => setImmediate(resolve)); };
const deferred = () => { let resolve, reject; const promise = new Promise((a, b) => { resolve = a; reject = b; }); return { promise, resolve, reject }; };
function setup(section = 'general') {
    const calls = [], listeners = new Set(), timers = new Map(), storage = new Map();
    const context = {
        console, AbortController, URLSearchParams, t:key => key, showToast() {},
        setTimeout, clearTimeout,
        setInterval(fn) { const id = timers.size + 1; timers.set(id, fn); return id; },
        clearInterval(id) { timers.delete(id); },
        document:{hidden:false, addEventListener(_event, fn) { listeners.add(fn); }, removeEventListener(_event, fn) { listeners.delete(fn); }},
        localStorage:{getItem:key => storage.get(key), removeItem:key => storage.delete(key), setItem:(key, value) => storage.set(key, value)},
        api:async (url, options) => {
            calls.push({url, options});
            const data = url.includes('/logs?') ? {data:[], page:1, total:0, total_pages:1} : url === '/settings/wp-package' ? {available:true} : url.includes('/updates/status') ? {status:'idle'} : [];
            return {success:true, data};
        },
    };
    vm.createContext(context); vm.runInContext(source, context);
    const pages = ['wpPackage', 'dbBackup', 'operationLogs', 'systemUpdate', 'panelCertificateSettings'].map(name => {
        const page = context[name](); page.activeSection = section;
        page.$watch = (_name, fn) => { page.changed = fn; return () => { page.changed = null; }; };
        return page;
    });
    const activate = async (page, value) => { page.activeSection = value; if (page.changed) await page.changed(); await settle(); };
    return {context, pages, calls, listeners, timers, storage, activate};
}

test('hidden settings sections make no ordinary API reads and warm tab changes reuse data', async () => {
    const {pages, calls, activate, listeners} = setup();
    for (const page of pages) await page.init();
    await settle();
    assert.deepEqual(calls.map(c => c.url), ['/settings/panel-certificate']);
    await activate(pages[0], 'wordpress');
    assert.equal(calls.filter(c => c.url === '/settings/wp-package').length, 1);
    await activate(pages[0], 'general'); await activate(pages[0], 'wordpress');
    assert.equal(calls.filter(c => c.url === '/settings/wp-package').length, 1);
    for (const page of pages) page.destroy();
    assert.equal(listeners.size, 0);
});

test('rapid log searches cancel superseded reads and cannot publish stale results', async () => {
    const {pages, context} = setup('logs'); const page = pages[2], pending = [];
    context.api = (url, options) => new Promise(resolve => pending.push({url, options, resolve}));
    page.query = 'first'; const first = page.fetchLogs();
    page.query = 'second'; const second = page.fetchLogs();
    assert.equal(pending[0].options.signal.aborted, true);
    assert(pending[1].url.includes('q=second'));
    assert.equal(pending[1].options.timeout, 15000);
    pending[1].resolve({success:true, data:{data:[{id:2}], page:1}}); await second;
    pending[0].resolve({success:true, data:{data:[{id:1}], page:1}}); await first;
    assert.equal(page.logs[0].id, 2); assert.equal(page.loading, false);
});

test('leaving a section cancels a pending read, and an immediate return loads again', async () => {
    const {pages, context, activate} = setup('wordpress'); const page = pages[0], pending = [];
    context.api = (_url, options) => new Promise(resolve => pending.push({options, resolve}));
    page.init(); await settle();
    await activate(page, 'general');
    assert(pending[0].options.signal.aborted);
    page.activeSection = 'wordpress'; page.changed();
    pending[0].resolve({success:true, data:{available:true, version:'old'}}); await settle();
    assert.equal(pending.length, 2);
    pending[1].resolve({success:true, data:{available:true, version:'new'}}); await settle();
    assert.equal(page.pkg.version, 'new'); page.destroy();
});

test('failed backup and package reads remain unknown and do not become empty success', async () => {
    const {pages, context} = setup();
    context.api = async () => { throw new Error('Offline'); };
    for (const [page, method] of [[pages[0], 'fetchStatus'], [pages[1], 'fetchBackups']]) {
        assert.equal(await page[method](), false);
        assert.equal(page.loaded, false); assert.equal(page.loadError, 'Offline');
    }
    assert.match(html, /x-model="query" @input\.debounce\.400ms="applyFilters\(\)"/);
});

test('certificate polling pauses off-section but continues for a known running task', async () => {
    const {pages, calls, timers, activate} = setup(); const page = pages[4];
    await page.init(); const poll = [...timers.values()][0];
    await activate(page, 'logs'); poll(); await settle();
    assert.equal(calls.length, 1);
    page.status.running = true; poll(); await settle();
    assert.equal(calls.length, 2); page.destroy();
});

test('a system update response arriving after page destruction cannot restart polling', async () => {
    const {pages, context} = setup('updates'); const page = pages[3];
    let pending;
    context.api = () => new Promise(resolve => { pending = resolve; });
    const read = page.resume(); page.destroy();
    pending({success:true, data:{status:'running', message:'running'}}); await read;
    assert.equal(page.pollTimer, null); assert.equal(page.updating, false);
});

test('panel settings reads preserve draft fields through failure and retry and reject stale responses', async () => {
    const {context} = setup(), pending = [];
    context.api = (url, options) => { const request = deferred(); pending.push({url, options, ...request}); return request.promise; };
    const page = context.panelSettings(), first = page.fetchSettings();
    page.panelTitle = 'Unsaved title'; page.username = 'draft-user'; page.autoUpdate.window = '08:00-09:00';
    pending[0].reject(Error('offline')); await first; assert.equal(page.accountLoaded, false);
    const retry = page.fetchSettings(), newer = page.fetchSettings();
    pending[2].resolve({success:true,data:{username:'actual-user',basic_auth_user:'gateway',panel_title:'Saved title',hostname:'new-host',panel_auto_update:{panel_auto_update_enabled:'true'}}}); await newer;
    pending[1].resolve({success:true,data:{username:'old-user',basic_auth_user:'old-gateway',hostname:'old-host'}}); await retry;
    assert.equal(page.panelTitle, 'Unsaved title'); assert.equal(page.username, 'draft-user'); assert.equal(page.originalUsername, 'actual-user');
    assert.equal(page.basicAuthUser, 'gateway'); assert.equal(page.hostname, 'new-host'); assert.equal(page.autoUpdate.enabled, true); assert.equal(page.autoUpdate.window, '08:00-09:00');
    assert.equal(page.accountLoaded, true); assert.equal(page.accountLoadError, ''); assert(pending.every(request => request.url === '/settings' && !request.options.method)); page.destroy();
});

test('a saved settings snapshot advances its baseline without consuming newer edits', async () => {
    const {context} = setup(), pending = deferred(), calls = [];
    let data = {username:'admin',basic_auth_user:'gateway',panel_title:'Original',hostname:'old-host'};
    context.api = async (url, options) => { calls.push({url, options}); return options?.method ? pending.promise : {success:true,data}; };
    const page = context.panelSettings(); await page.fetchSettings(); page.panelTitle = 'Submitted';
    const saving = page.saveBasic(); page.panelTitle = 'Newer draft'; pending.resolve({success:true}); await saving;
    data = {...data,panel_title:'Submitted',hostname:'current-host'}; await page.fetchSettings();
    assert.equal(page.panelTitle, 'Newer draft'); assert.equal(page.hostname, 'current-host');
    assert.equal(calls.filter(call => call.options?.method).length, 1); assert.equal(calls[1].options.method, 'PUT'); assert.equal(calls[1].options.body.panel_title, 'Submitted');
    page.panelTitle = 'Submitted'; data = {...data,panel_title:'External update'}; await page.fetchSettings(); assert.equal(page.panelTitle, 'External update'); page.destroy();
});

test('Basic Auth completion clears only unchanged submitted secrets and leaves other form feedback idle', async () => {
    const {context} = setup(), pending = deferred(), calls = [];
    context.api = (url, options) => { calls.push({url, options}); return pending.promise; };
    const page = context.panelSettings(); page.accountLoaded = true; page.basicAuthUser = 'gateway';
    page.pw.basic = 'submitted-password'; page.pw.basicCurrent = 'current-password'; page.pw.basicCode = ' 123456 ';
    const saving = page.saveBasicAuth(); page.pw.basic = 'newer-password'; page.pw.basicCode = '654321'; page.pw.new1 = 'other-form-draft';
    assert.equal(page.accountSaving, 'basic'); assert.equal(page.ntpSyncing, false); assert.equal(page.proxyTesting, false);
    pending.resolve({success:true}); await saving;
    assert.equal(page.pw.basic, 'newer-password'); assert.equal(page.pw.basicCurrent, ''); assert.equal(page.pw.basicCode, '654321'); assert.equal(page.pw.new1, 'other-form-draft');
    assert.equal(calls.length, 1); assert.equal(calls[0].url, '/settings'); assert.equal(calls[0].options.body.basic_auth_password, 'submitted-password'); assert.equal(calls[0].options.body.code, '123456');
});

test('WordPress package refresh cannot replace a newer auto-check choice, including after a failed save', async () => {
    const {context, pages} = setup(), page = pages[0], read = deferred(), write = deferred(), calls = [];
    await page.fetchStatus();
    context.api = (url, options) => { calls.push({url, options}); return options?.method ? write.promise : read.promise; };
    const refresh = page.fetchStatus(); page.autoCheck.enabled = false; const saving = page.saveAutoCheck();
    read.resolve({success:true,data:{available:true,version:'new-package',auto_check:{wp_package_auto_check_enabled:'true'}}}); await refresh;
    assert.equal(page.pkg.version, 'new-package'); assert.equal(page.autoCheck.enabled, false);
    write.resolve({success:false,message:'not saved'}); await saving; assert.equal(page.autoCheckSaving, false);
    await page.fetchStatus(); assert.equal(page.autoCheck.enabled, false);
    assert.equal(calls.filter(call => call.options?.method).length, 1); assert.equal(calls[1].url, '/settings'); assert.equal(calls[1].options.body.wp_package_auto_check_enabled, 'false');
});

test('rapid WordPress auto-check edits serialize immutable requests and persist the latest choice', async () => {
    const {context, pages} = setup(), page = pages[0], writes = [];
    await page.fetchStatus();
    context.api = (url, options) => { const pending = deferred(); writes.push({url, options, ...pending}); return pending.promise; };
    page.autoCheck.enabled = false; const first = page.saveAutoCheck(); page.autoCheck.enabled = true; await page.saveAutoCheck();
    assert.equal(writes.length, 1); assert.equal(writes[0].options.body.wp_package_auto_check_enabled, 'false');
    writes[0].resolve({success:true}); await settle(); assert.equal(writes.length, 2); assert.equal(writes[1].options.body.wp_package_auto_check_enabled, 'true');
    writes[1].resolve({success:true}); await first; assert.equal(page.autoCheckSaving, false); assert.equal(page.savedAutoCheckEnabled, true);
    assert(writes.every(request => request.url === '/settings' && request.options.method === 'PUT'));
});

test('automatic panel update edits serialize the latest full snapshot without locking unrelated controls', async () => {
    const {context} = setup(), page = context.panelSettings(), writes = [];
    page.accountLoaded = true;
    context.api = (url, options) => { const pending = deferred(); writes.push({url, options, ...pending}); return pending.promise; };
    page.autoUpdate.enabled = true; const saving = page.saveAutoUpdate();
    page.autoUpdate.mode = 'all_stable'; await page.saveAutoUpdate(); page.autoUpdate.window = '08:00-09:00'; page.autoUpdate.delay = 30; await page.saveAutoUpdate();
    assert.equal(writes.length, 1); assert.equal(writes[0].options.body.panel_auto_update_mode, 'patch_only'); assert.equal(writes[0].options.body.panel_auto_update_window, '03:00-05:00');
    assert.equal(page.accountSaving, ''); assert.equal(page.ntpSyncing, false); assert.equal(page.proxyTesting, false); assert.equal(page.accountLoaded, true);
    writes[0].resolve({success:true}); await settle(); assert.equal(writes.length, 2);
    assert.deepEqual(JSON.parse(JSON.stringify(writes[1].options.body)), {panel_auto_update_enabled:'true',panel_auto_update_mode:'all_stable',panel_auto_update_window:'08:00-09:00',panel_auto_update_release_delay_minutes:'30',panel_auto_update_signature_timeout_minutes:'120'});
    writes[1].resolve({success:true}); await saving; assert.equal(page.autoUpdateSaving, false); assert.equal(page.autoUpdatePending, false); assert.equal(page.autoUpdateBaseline.window, '08:00-09:00');
    assert(writes.every(request => request.url === '/settings' && request.options.method === 'PUT'));
});

test('failed automatic update save retains newer edits, releases the queue, and waits for explicit retry', async () => {
    const {context} = setup(), page = context.panelSettings(), writes = [];
    page.accountLoaded = true;
    context.api = (url, options) => { const pending = deferred(); writes.push({url, options, ...pending}); return pending.promise; };
    const saving = page.saveAutoUpdate(); page.autoUpdate.window = '10:00-11:00'; await page.saveAutoUpdate();
    writes[0].resolve({success:false,message:'write failed'}); await saving; assert.equal(writes.length, 1); assert.equal(page.autoUpdateSaving, false); assert.equal(page.autoUpdatePending, false); assert.equal(page.autoUpdate.window, '10:00-11:00'); assert.equal(page.autoUpdateBaseline, null);
    const retry = page.saveAutoUpdate(); assert.equal(writes[1].options.body.panel_auto_update_window, '10:00-11:00'); writes[1].resolve({success:true}); await retry; assert.equal(page.autoUpdateBaseline.window, '10:00-11:00');
});

test('unknown restore status retains the job ID and blocks a second restore or backup', async () => {
    const {pages, context, storage, calls} = setup(); const page = pages[1];
    storage.set('olsWPanelDBRestoreID', 'running-job');
    context.setTimeout = fn => { queueMicrotask(fn); return 1; };
    context.api = async url => { calls.push({url}); throw new Error('Restarting'); };
    await page.waitForRestore('running-job');
    assert.equal(page.restoring, true); assert.equal(page.restorePolling, false);
    assert.equal(page.restoreStatusError, 'settings.panel_db_restore_status_unknown');
    assert.equal(storage.get('olsWPanelDBRestoreID'), 'running-job');
    const count = calls.length; await page.doBackup(); await page.doRestore('old.db');
    assert.equal(calls.length, count);
});

test('update confirmation prevents duplicate writes for both panel and system updates', async () => {
    for (const factory of ['versionCheck', 'systemUpdate']) {
        const {context} = setup();
        const page = context[factory]();
        let confirm, confirmations = 0, writes = 0;
        context.confirmModal = () => { confirmations++; return new Promise(resolve => { confirm = resolve; }); };
        context.api = async url => {
            if (url.endsWith('/do')) writes++;
            return {success:true, data:url.includes('/system/') ? {status:'running'} : {running:false, completed:true}};
        };
        const first = page.doUpdate(); await page.doUpdate();
        assert.equal(confirmations, 1); assert.equal(writes, 0);
        confirm(true); await first;
        assert.equal(writes, 1); page.destroy();
    }
});

test('accepted panel update plus unavailable status cannot invent completion', async () => {
    const {context} = setup(); const page = context.versionCheck();
    context.confirmModal = async () => true;
    context.api = async url => { if (url === '/update/status') throw new Error('Restarting'); return {success:true, data:{message:'Restart and health check pending'}}; };
    await page.doUpdate();
    assert.equal(page.updateStatus.completed, false);
    assert.equal(page.updateStatus.running, true);
    assert.notEqual(page.updateStatus.percent, 100);
    page.destroy();
});

test('historic system update success reuses a warm section and probes packages once', async () => {
    const {context, pages, activate, calls} = setup('updates'); const page = pages[3];
    context.api = async url => {
        calls.push({url});
        return {success:true,data:url.endsWith('/status') ? {id:'old-job',status:'success',updated_at:'2026-10-11T10:00:00Z',remaining_count:0} : {packages:[],count:0}};
    };
    page.init(); await settle();
    assert.equal(calls.filter(c => c.url.startsWith('/system/updates') && !c.url.endsWith('/status')).length, 1);
    await activate(page, 'general'); await activate(page, 'updates');
    assert.equal(calls.filter(c => c.url.startsWith('/system/updates')).length, 2);
    page.destroy();
});

test('a running update received during confirmation prevents a second write', async () => {
    for (const factory of ['versionCheck', 'systemUpdate']) {
        const {context} = setup(); const page = context[factory]();
        let confirm, writes = 0;
        context.confirmModal = () => new Promise(resolve => { confirm = resolve; });
        context.api = async () => { writes++; return {success:true,data:{status:'running'}}; };
        const action = page.doUpdate(); page.updating = true; confirm(true); await action;
        assert.equal(writes, 0); page.destroy();
    }
});

test('lost update POST response preserves authoritative running state and blocks retry', async () => {
    const {context} = setup(); const page = context.versionCheck(); let writes = 0;
    context.confirmModal = async () => true;
    context.api = async url => {
        if (url === '/update/do') { writes++; throw new Error('Response lost'); }
        return {success:true,data:{running:true,completed:false,stage:'download_binary',percent:30}};
    };
    await page.doUpdate(); await page.doUpdate();
    assert.equal(writes, 1); assert.equal(page.updateStatus.running, true); assert.equal(page.updating, true);
    assert.equal(page.updateStatus.stage, 'download_binary'); assert.equal(page.updateStatus.percent, 30);
    page.destroy();
});
