const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const {test} = require('node:test');

const controller = fs.readFileSync(path.join(__dirname, '../../web/templates/firewall_controller.html'), 'utf8').match(/<script>([\s\S]*?)<\/script>/)[1];
const template = fs.readFileSync(path.join(__dirname, '../../web/templates/firewall_access.html'), 'utf8');
const clone = value => JSON.parse(JSON.stringify(value));
const publicRule = (port, protocol = 'tcp') => ({protocol, port, source:''});
const deferred = () => { let resolve; const promise = new Promise(done => { resolve = done; }); return {promise, resolve}; };

function setup({metadata = {public_exposure:[]}, requiresConfirmation = false, savedPublic = []} = {}) {
    const calls = [], dialogs = [], notices = [], timers = new Map(); let timerID = 0;
    const state = {status:{access_available:true, access_enabled:true, ssh_port:2526, panel_port:8443, listeners:[], rules:[], access_rules:[publicRule(2526), publicRule(8443), publicRule(80), publicRule(443), ...savedPublic]}};
    const context = {
        t:(key, values) => key + (values?.ports ? ': '+values.ports : ''),
        showToast:(...args) => notices.push(args),
        confirmModal:async message => { dialogs.push(message); return true; },
        setTimeout:(callback, delay) => { const id = ++timerID; timers.set(id, {callback, delay}); return id; },
        clearTimeout:id => timers.delete(id),
        api:async (url, options = {}) => {
            calls.push({url, options:clone(options)});
            if (url.endsWith('/access/preview')) return {success:true, data:{rules:clone(options.body.rules), fingerprint:'reviewed-public-draft', ssh_port:2526, panel_port:8443, requires_confirmation:requiresConfirmation, requires_ssh_validation:false, ...clone(metadata)}};
            if (url.endsWith('/access/apply')) {
                state.status.access_rules = clone(options.body.rules);
                return {success:true, data:requiresConfirmation ? {saved:false, requires_confirmation:true, confirmation_token:'pending-public-token', change_id:'c'.repeat(32), deadline:'2030-01-01'} : {saved:true, requires_confirmation:false}};
            }
            if (url === '/firewall/ports') return {success:true, data:clone(state.status)};
            throw Error('unexpected API: '+url);
        },
    };
    vm.createContext(context); vm.runInContext(controller, context);
    const page = context.firewallManager('ports'); page.portStatus = clone(state.status); page.resetAccessRows();
    return {page, context, state, calls, dialogs, notices, timers};
}

function selectPublic(page, ports = [7080]) {
    for (const port of ports) page.accessRows.find(row => row.port === port && row.protocol === 'tcp').scope = 'public';
    page.markAccessDirty();
}

function applications(calls) { return calls.filter(call => call.url.endsWith('/access/apply')); }

test('sensitive ports allow explicit public selection while new policies retain closed defaults', () => {
    const option = template.match(/<option\b[^>]*\bvalue="public"[^>]*>/)?.[0];
    assert(option); assert(!/\bdisabled\b/.test(option), 'public scope must be selectable for every service');
    const {page} = setup();
    for (const access_enabled of [false, true]) {
        page.portStatus.access_enabled = access_enabled; page.resetAccessRows();
        for (const port of [7080,3306,6379]) {
            assert.equal(page.accessSensitive({port}), true);
            assert.equal(page.accessRows.find(row => row.port === port).scope, 'closed');
            assert(!page.accessPayload().some(rule => rule.port === port));
        }
    }
    const select = template.match(/<select\b[^>]*x-model="row.scope"[^>]*>/)?.[0];
    assert(select?.includes(':aria-describedby="accessSensitive(row) && row.scope===\'public\''));
    assert(template.includes('x-show="accessSensitive(row) && row.scope===\'public\'"'));
    assert(template.includes('firewall.access_public_sensitive_help'));
});

for (const port of [7080,3306,6379]) {
    test('public '+port+' requires the affected port confirmation and sends the matching affirmative receipt', async () => {
        const {page, calls, dialogs, timers} = setup({metadata:{public_exposure:[publicRule(port)]}});
        selectPublic(page, [port]); await page.startAccessSave();
        assert.deepEqual(dialogs, ['firewall.access_public_sensitive_confirm: '+port+'/TCP']);
        assert.equal(applications(calls).length, 1);
        const request = applications(calls)[0].options.body;
        assert.equal(request.confirm_public, true); assert.equal(request.fingerprint, 'reviewed-public-draft');
        assert(request.rules.some(rule => rule.port === port && rule.protocol === 'tcp' && rule.source === ''));
        assert.equal(page.accessDirty, false); assert.equal(page.accessBusy, false); assert.equal(timers.size, 0);
    });
}

test('one confirmation lists all newly public sensitive services without unrelated ordinary ports', async () => {
    const ports = [7080,3306,6379];
    const {page, calls, dialogs} = setup({metadata:{public_exposure:ports.map(port => publicRule(port))}});
    selectPublic(page, ports); await page.startAccessSave();
    assert.deepEqual(dialogs, ['firewall.access_public_sensitive_confirm: 7080/TCP, 3306/TCP, 6379/TCP']);
    assert.equal(applications(calls).length, 1); assert.equal(applications(calls)[0].options.body.confirm_public, true);
});

test('management review and public exposure combine into one modal while retaining rollback confirmation', async () => {
    const {page, calls, dialogs, timers} = setup({requiresConfirmation:true, metadata:{public_exposure:[publicRule(7080)]}});
    selectPublic(page); await page.startAccessSave();
    assert.equal(dialogs.length, 0); assert.equal(applications(calls).length, 0, 'management changes first retain their review stage');
    await page.applyAccess();
    assert.deepEqual(dialogs, ['firewall.access_public_sensitive_confirm: 7080/TCP\n\nfirewall.access_apply_confirm']);
    assert.equal(applications(calls)[0].options.body.confirm_public, true);
    assert.equal(page.accessToken, 'pending-public-token'); assert.equal(timers.size, 2);
    assert(!calls.some(call => call.url.endsWith('/access/confirm')), 'public consent never bypasses management connection verification');
});

for (const requiresConfirmation of [false, true]) {
    test('cancelling public exposure preserves the draft and sends no policy for management review '+requiresConfirmation, async () => {
        const {page, context, calls, timers} = setup({requiresConfirmation, metadata:{public_exposure:[publicRule(7080)]}});
        selectPublic(page); await page.previewAccess(); const review = page.accessPreview;
        context.confirmModal = async () => false; await page.applyAccess();
        assert.equal(applications(calls).length, 0); assert.equal(page.accessPreview, review);
        assert.equal(page.accessDirty, true); assert.equal(page.accessBusy, false); assert.equal(page.accessToken, ''); assert.equal(timers.size, 0);
    });
}

for (const change of ['edited draft','replaced review','SSH state changed','policy became unavailable']) {
    test('affirmative public consent cannot apply a stale '+change, async () => {
        const {page, context, calls} = setup({metadata:{public_exposure:[publicRule(7080)]}}), confirmation = deferred();
        selectPublic(page); await page.previewAccess();
        context.confirmModal = () => confirmation.promise; const pending = page.applyAccess();
        assert.equal(page.accessBusy, true); await page.applyAccess();
        if (change === 'edited draft') { page.accessRows.find(row => row.port === 7080).scope = 'closed'; page.markAccessDirty(); }
        if (change === 'replaced review') page.accessPreview = {...page.accessPreview, fingerprint:'different-review'};
        if (change === 'SSH state changed') page.accessSSHStale = true;
        if (change === 'policy became unavailable') page.portStatus.access_available = false;
        confirmation.resolve(true); await pending;
        assert.equal(applications(calls).length, 0); assert.equal(page.accessBusy, false); assert.equal(page.accessToken, '');
    });
}

test('an unchanged public sensitive rule stays public and ordinary saves do not prompt again', async () => {
    const {page, calls, dialogs} = setup({savedPublic:[publicRule(7080)]});
    assert.equal(page.accessRows.find(row => row.port === 7080).scope, 'public');
    page.accessCustomPort = '8088'; page.addAccessRow(); await page.startAccessSave();
    assert.equal(dialogs.length, 0); assert.equal(applications(calls)[0].options.body.confirm_public, false);
    assert(applications(calls)[0].options.body.rules.some(rule => rule.port === 7080 && rule.source === ''));
});

for (const metadata of [{}, {public_exposure:null}, {public_exposure:[]}]) {
    test('absent or empty exposure metadata never invents public consent '+JSON.stringify(metadata), async () => {
        const {page, calls, dialogs} = setup({metadata, savedPublic:[publicRule(7080)]});
        page.accessCustomPort = '8088'; page.addAccessRow(); await page.startAccessSave();
        assert.equal(dialogs.length, 0); assert.equal(applications(calls)[0].options.body.confirm_public, false);
    });
}

test('missing exposure metadata cannot grant public consent for a new sensitive port', async () => {
    const {page, context, calls, dialogs, notices} = setup({metadata:{}}), api = context.api;
    context.api = async (url, options = {}) => {
        if (url.endsWith('/access/apply')) {
            calls.push({url, options:clone(options)});
            return {success:false, message:'public consent required'};
        }
        return api(url, options);
    };
    selectPublic(page); await page.startAccessSave();
    assert.equal(dialogs.length, 0); assert.equal(applications(calls)[0].options.body.confirm_public, false);
    assert.equal(page.accessDirty, true); assert.equal(page.accessToken, '');
    assert(!notices.some(notice => notice[1] === 'success'));
});

for (const exposure of [
    true, {}, '7080', [null], [publicRule(80)], [publicRule('7080')], [publicRule(7080, 'icmp')],
    [{protocol:'tcp', port:7080}], [{protocol:'tcp', port:7080, source:'198.51.100.2/32'}],
    [publicRule(3306)], [publicRule(7080, 'udp')],
]) {
    test('malformed or mismatched exposure metadata never opens a port '+JSON.stringify(exposure), async () => {
        const {page, calls, dialogs, notices} = setup({metadata:{public_exposure:exposure}});
        selectPublic(page); await page.startAccessSave();
        assert.equal(dialogs.length, 0); assert.equal(applications(calls).length, 0);
        assert.equal(page.accessPreview, null); assert.equal(page.accessBusy, false); assert.equal(page.accessDirty, true);
        assert(!notices.some(notice => notice[1] === 'success')); assert(page.accessError.includes('common.operation_failed'));
    });
}

test('a CIDR-specific sensitive service requires no public-exposure consent', async () => {
    const {page, calls, dialogs} = setup();
    const row = page.accessRows.find(row => row.port === 7080); row.scope = 'specific'; row.sources = '198.51.100.2/32'; page.markAccessDirty();
    await page.startAccessSave();
    assert.equal(dialogs.length, 0); assert.equal(applications(calls)[0].options.body.confirm_public, false);
    assert(applications(calls)[0].options.body.rules.some(rule => rule.port === 7080 && rule.source === '198.51.100.2/32'));
});

test('the legacy public port form retains its explicit source and operation confirmations for WebAdmin', async () => {
    const {page, context, calls, dialogs} = setup();
    page.portStatus.access_enabled = false;
    page.portForm = {...page.portForm, port:7080, source_mode:'any', source:''};
    const api = context.api;
    context.api = async (url, options = {}) => {
        if (url === '/firewall/ports' && options.method === 'POST') { calls.push({url, options:clone(options)}); return {success:true}; }
        return api(url, options);
    };
    await page.addPortRule();
    assert.deepEqual(dialogs, ['firewall.confirm_any_source','firewall.confirm_open_port']);
    const write = calls.find(call => call.options.method === 'POST');
    assert.equal(write.options.body.port, 7080); assert.equal(write.options.body.confirm_public, true); assert.equal(page.portSubmitting, false);
});
