const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const {test} = require('node:test');

const controller = fs.readFileSync(path.join(__dirname, '../../web/templates/firewall_controller.html'), 'utf8');
const portsHTML = fs.readFileSync(path.join(__dirname, '../../web/templates/firewall_ports.html'), 'utf8');
const source = controller.match(/<script>([\s\S]*?)<\/script>/)[1];
const deferred = () => { let resolve, reject; const promise = new Promise((a,b) => { resolve = a; reject = b; }); return {promise, resolve, reject}; };
const settle = async () => { for (let i = 0; i < 3; i++) await new Promise(resolve => setImmediate(resolve)); };
const clone = value => JSON.parse(JSON.stringify(value));

function setup() {
    const calls = [], confirmations = [], notices = [], timers = new Map(); let timerID = 0;
    const state = {status:{backend:'nftables', writable:true, access_available:true, access_enabled:false, ssh_port:2222, panel_port:9443, current_management_ip:'203.0.113.9', listeners:[], rules:[{id:7, protocol:'tcp', port:12345, source:'203.0.113.9/32'}], access_rules:[]}};
    const context = {
        t:key => key, showToast:(...args) => notices.push(args),
        confirmModal:async message => { confirmations.push(message); return true; },
        setTimeout(callback, delay) { const id = ++timerID; timers.set(id,{callback,delay}); return id; },
        clearTimeout:id => timers.delete(id),
        api:async (url, options = {}) => {
            calls.push({url, options});
            if (url === '/firewall/ports' && !options.method) return {success:true, data:clone(state.status)};
            if (url === '/firewall/ports' && options.method === 'POST') return {success:true, data:{}};
            if (url === '/firewall/ports/7' && options.method === 'DELETE') return {success:true, data:{}};
            if (url.endsWith('/access/preview')) return {success:true, data:{rules:clone(options.body.rules), fingerprint:'test-fingerprint', existing_rules:''}};
            if (url.endsWith('/access/apply')) {
                state.status.access_enabled = true; state.status.access_rules = clone(options.body.rules);
                return {success:true, data:{confirmation_token:'pending-token', deadline:'2030-01-01T00:00:00Z'}};
            }
            if (url.endsWith('/access/confirm')) return {success:true, data:{}};
            throw new Error('Unexpected API: ' + url);
        },
    };
    vm.createContext(context); vm.runInContext(source,context);
    const page = context.firewallManager('ports'); page.portStatus = clone(state.status); page.resetAccessRows();
    page.portForm = {protocol:'tcp', port:12346, source:'203.0.113.9/32', source_mode:'specific', description:'test legacy', duration_mode:'temporary', duration_minutes:60};
    return {page, context, calls, confirmations, notices, timers, state};
}
function draft(page) {
    page.accessCustomPort = '8088'; page.addAccessRow();
    const row = page.accessRows.find(item => item.port === 8088); row.scope = 'specific'; row.sources = '198.51.100.8/32'; page.markAccessDirty();
    return clone(page.accessRows);
}
const legacy = page => page.deletePortRule({id:7, protocol:'tcp', port:12345});
const mutate = (page, kind) => kind === 'add' ? page.addPortRule() : legacy(page);
const mutations = calls => calls.filter(call => call.options.method && !call.url.includes('/access/'));

for (const kind of ['add','delete']) {
    for (const blocked of ['strict policy', 'pending verification', 'policy operation']) {
        test(kind + ' rechecks ' + blocked + ' after waiting for confirmation', async () => {
            const {page, context, calls} = setup(), confirmation = deferred();
            context.confirmModal = () => confirmation.promise;
            const pending = mutate(page,kind);
            assert.equal(page.portSubmitting,true,'the legacy operation owns its lock while the dialog is open');
            if (blocked === 'strict policy') page.portStatus.access_enabled = true;
            else if (blocked === 'pending verification') page.accessToken = 'new-policy-token';
            else page.accessBusy = true;
            confirmation.resolve(true); await pending;
            assert.equal(mutations(calls).length,0); assert.equal(page.portSubmitting,false);
        });
    }

    test(kind + ' confirmation uses one shared lock against duplicate and conflicting legacy or policy actions', async () => {
        const {page, context, calls} = setup(), confirmation = deferred(); let confirmationCount = 0;
        context.confirmModal = () => { confirmationCount++; return confirmation.promise; };
        page.accessPreview = {rules:page.accessPayload(),fingerprint:'existing-preview'};
        const first = mutate(page,kind);
        await mutate(page,kind); await mutate(page,kind === 'add' ? 'delete' : 'add');
        await page.previewAccess(); await page.applyAccess();
        assert.equal(confirmationCount,1); assert.equal(calls.length,0); assert.equal(page.portSubmitting,true);
        confirmation.resolve(true); await first;
        assert.equal(mutations(calls).length,1); assert.equal(page.portSubmitting,false);
    });

    test(kind + ' cancellation releases the shared lock without changing rules', async () => {
        const {page, context, calls} = setup(); context.confirmModal = async () => false;
        await mutate(page,kind);
        assert.equal(calls.length,0); assert.equal(page.portSubmitting,false);
    });

    test(kind + ' API failure releases the shared lock and leaves policy drafts intact', async () => {
        const {page, context, notices} = setup(), before = draft(page);
        context.api = async () => { throw new Error('legacy write failed'); };
        await mutate(page,kind);
        assert.equal(page.portSubmitting,false); assert.equal(page.accessDirty,true); assert.deepEqual(clone(page.accessRows),before);
        assert(notices.some(notice => notice[0] === 'legacy write failed'));
    });

    test(kind + ' implicit status refresh keeps the unsaved custom-port draft and invalidates its old preview', async () => {
        const {page, calls} = setup(), before = draft(page);
        page.accessPreview = {rules:page.accessPayload(),fingerprint:'stale-preview'};
        await mutate(page,kind);
        assert.equal(mutations(calls).length,1); assert.equal(page.accessDirty,true);
        assert.deepEqual(clone(page.accessRows),before); assert.equal(page.accessPreview,null);
        assert.equal(page.portsLoaded,true); assert.equal(page.portSubmitting,false);
    });
}

test('ordinary status refresh updates observations but preserves all draft scopes and sources', async () => {
    const {page, state} = setup(), before = draft(page);
    page.accessPreview = {rules:page.accessPayload(),fingerprint:'stale-preview'};
    state.status.listener_count = 9;
    await page.fetchPortStatus();
    assert.equal(page.portStatus.listener_count,9); assert.deepEqual(clone(page.accessRows),before);
    assert.equal(page.accessDirty,true); assert.equal(page.accessPreview,null); assert.equal(page.portsLoading,false);
});

test('the actual SSH-port-changed handler keeps an existing draft while updating the observed SSH port', async () => {
    const {page, state} = setup(), before = draft(page);
    page.accessPreview = {rules:page.accessPayload(),fingerprint:'stale-preview'}; state.status.ssh_port = 3333;
    const handler = portsHTML.match(/@ssh-port-changed\.window="([^"]+)"/)?.[1]; assert(handler);
    await vm.runInNewContext('with (page) { ' + handler + ' }', {page});
    assert.equal(page.portStatus.ssh_port,3333); assert.deepEqual(clone(page.accessRows),before);
    assert.equal(page.accessDirty,true); assert.equal(page.accessPreview,null);
});

test('explicit refresh requires consent before discarding a draft, and accepted refresh loads current rules', async () => {
    const {page, context, calls} = setup(), before = draft(page);
    context.confirmModal = async () => false; await page.refreshAccess();
    assert.equal(calls.length,0); assert.equal(page.accessDirty,true); assert.deepEqual(clone(page.accessRows),before);
    context.confirmModal = async () => true; await page.refreshAccess();
    assert.equal(calls.length,1); assert.equal(page.accessDirty,false); assert.equal(page.accessRows.some(row => row.port === 8088),false);
});

test('applying a preview synchronizes the applied policy but retains the separate explicit verification step', async () => {
    const {page, calls, timers} = setup(); draft(page);
    await page.previewAccess(); assert.equal(page.accessDirty,true);
    await page.applyAccess();
    assert.equal(page.accessDirty,false); assert.equal(page.portStatus.access_enabled,true); assert.equal(page.accessPreview,null);
    const custom = page.accessRows.find(row => row.port === 8088); assert.equal(custom.scope,'specific'); assert.equal(custom.sources,'198.51.100.8/32');
    assert.equal(page.accessToken,'pending-token'); assert.equal(page.accessChecked,false);
    assert.equal(calls.some(call => call.url.endsWith('/access/confirm')),false);
    await page.confirmAccess(); assert.equal(calls.some(call => call.url.endsWith('/access/confirm')),false);
    page.accessChecked = true; await page.confirmAccess();
    assert.equal(calls.filter(call => call.url.endsWith('/access/confirm')).length,1); assert.equal(page.accessToken,''); assert.equal(timers.size,0);
});

test('rollback refresh restores observed rules and cannot leave an unapplied custom port in the saved policy', async () => {
    const {page, state, timers} = setup(); draft(page); await page.previewAccess(); await page.applyAccess();
    const rollback = [...timers.values()][0]; assert(rollback); assert.equal(page.accessToken,'pending-token');
    state.status.access_enabled = false; state.status.access_rules = [];
    rollback.callback(); await settle();
    assert.equal(page.accessToken,''); assert.equal(page.accessChecked,false); assert.equal(page.portStatus.access_enabled,false);
    assert.equal(page.accessDirty,false); assert.equal(page.accessRows.some(row => row.port === 8088),false);
});
