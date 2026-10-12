const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const {test} = require('node:test');

const html = fs.readFileSync(path.join(__dirname, '../../web/templates/settings.html'), 'utf8');
const source = [...html.matchAll(/<script[^>]*>([\s\S]*?)<\/script>/g)].map(m => m[1].replace(/{{[\s\S]*?}}/g, 'translated')).join('\n');
const settle = async () => { for (let i = 0; i < 4; i++) await new Promise(resolve => setImmediate(resolve)); };
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
