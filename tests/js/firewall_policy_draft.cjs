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
    const state = {now:Date.parse('2026-10-10T08:00:00Z'), status:{backend:'nftables', writable:true, access_available:true, access_enabled:false, ssh_port:2222, panel_port:9443, current_management_ip:'203.0.113.9', listeners:[], rules:[{id:7, protocol:'tcp', port:12345, source:'203.0.113.9/32'}], access_rules:[]}};
    const context = {
        Date:class extends Date { static now() { return state.now; } },
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
                state.status.access_change_id = 'c'.repeat(32); state.status.access_change_state = 'pending'; state.status.access_change_error = '';
                return {success:true, data:{confirmation_token:'pending-token', change_id:'c'.repeat(32), deadline:new Date(state.now + 70000).toISOString()}};
            }
            if (url.endsWith('/access/confirm')) { state.status.access_change_state = 'confirmed'; return {success:true, data:{confirmed:true}}; }
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

const observeSSH = page => {
    const handler = portsHTML.match(/@ssh-port-observed\.window="([^"]+)"/)?.[1]; assert(handler);
    return vm.runInNewContext('with (page) { ' + handler + ' }', {page});
};

test('an observed external SSH port change rebuilds an unchanged draft without migrating firewall rules', async () => {
    const {page, state, calls} = setup();
    state.status.access_enabled = true;
    state.status.access_rules = [{protocol:'tcp',port:2222,source:'203.0.113.9/32'},{protocol:'tcp',port:9443,source:''}];
    page.portStatus = clone(state.status); page.resetAccessRows();
    state.status.ssh_port = 22; await observeSSH(page);
    assert.equal(page.portStatus.ssh_port,22); assert.equal(page.accessDirty,false); assert.equal(page.accessSSHStale,false);
    const ssh = page.accessRows.find(row=>row.label==='SSH');
    assert.equal(ssh.port,22); assert.equal(ssh.fixed,true); assert.equal(ssh.scope,'closed');
    assert.equal(page.accessPayload().some(rule=>rule.port===22),false,'Observing a listener must not invent a firewall allowance.');
    assert(page.accessPayload().some(rule=>rule.port===2222 && rule.source==='203.0.113.9/32'));
    assert.deepEqual(calls.map(call=>[call.url,call.options.method]),[['/firewall/ports',undefined]]);
});

test('an external SSH port change pauses a dirty draft until the user accepts an explicit reload', async () => {
    const {page, state, context, calls} = setup(), before = draft(page);
    page.accessPreview = {rules:page.accessPayload(),fingerprint:'old-ssh-endpoint'};
    state.status.ssh_port = 22; await observeSSH(page);
    assert.equal(page.portStatus.ssh_port,22); assert.equal(page.accessSSHStale,true); assert.equal(page.accessPreview,null);
    assert.equal(page.accessError,'firewall.access_ssh_changed'); assert.deepEqual(clone(page.accessRows),before);
    const readCount = calls.length;
    await page.startAccessSave(); await page.applyAccess();
    assert.equal(calls.length,readCount,'A paused SSH draft cannot preview or apply old access rules.');
    page.accessCustomPort='8099'; page.addAccessRow();
    assert.equal(page.accessRows.some(row=>row.port===8099),false);
    assert.equal(page.canRemoveAccessRow(page.accessRows.find(row=>row.port===8088)),false);
    context.confirmModal = async()=>false; await page.refreshAccess();
    assert.equal(page.accessSSHStale,true); assert.deepEqual(clone(page.accessRows),before);
    context.confirmModal = async()=>true; await page.refreshAccess();
    assert.equal(page.accessSSHStale,false); assert.equal(page.accessDirty,false); assert.equal(page.accessError,'');
    assert.equal(page.accessRows.find(row=>row.label==='SSH').port,22);
    assert.equal(page.accessRows.some(row=>row.port===8088),false);
    assert.equal(calls.some(call=>call.options.method),false,'Reloading observations is read-only.');
});

test('a failed parent status read after SSH observation keeps the old editor locked until an explicit refresh succeeds', async () => {
    const {page,context,calls} = setup(), originalAPI=context.api, before=draft(page), response=deferred();
    page.accessPreview={rules:page.accessPayload(),fingerprint:'old'};
    context.api=()=>response.promise;
    const pending=observeSSH(page);
    assert.equal(page.portStatus.access_available,false); assert.equal(page.accessPreview,null); assert.equal(page.portsLoading,true);
    response.reject(Error('port status unavailable')); await pending;
    assert.equal(page.portStatus.access_available,false); assert.deepEqual(clone(page.accessRows),before);
    context.api=originalAPI; const count=calls.length;
    await page.previewAccess();
    page.accessPreview={rules:page.accessPayload(),fingerprint:'obsolete'}; await page.applyAccess();
    assert.equal(calls.length,count,'A failed read cannot leave a route to applying the stale policy.');
    await page.refreshAccess();
    assert.equal(page.portStatus.access_available,true); assert.equal(page.accessDirty,false); assert.equal(page.accessPreview,null);
});

for (const result of ['success','failure']) {
    test('a late preview ' + result + ' cannot restore an old SSH review or hide the external-change warning', async () => {
        const {page, state, context, notices} = setup(), response = deferred(), originalAPI = context.api;
        draft(page);
        context.api = (url,options)=>url.endsWith('/access/preview') ? response.promise : originalAPI(url,options);
        const pending = page.previewAccess();
        state.status.ssh_port = 22; await observeSSH(page);
        if (result==='success') response.resolve({success:true,data:{rules:[],fingerprint:'old'}});
        else response.reject(Error('old preview failure'));
        await pending;
        assert.equal(page.accessPreview,null); assert.equal(page.accessSSHStale,true); assert.equal(page.accessBusy,false);
        assert.equal(page.accessError,'firewall.access_ssh_changed'); assert.equal(notices.length,0);
    });
}

test('an external SSH change while application confirmation is open prevents the obsolete policy write', async () => {
    const {page, state, context, calls} = setup(), confirmation = deferred();
    draft(page); await page.previewAccess();
    context.confirmModal = ()=>confirmation.promise;
    const pending = page.applyAccess();
    state.status.ssh_port = 22; await observeSSH(page);
    confirmation.resolve(true); await pending;
    assert.equal(page.accessSSHStale,true); assert.equal(page.accessPreview,null); assert.equal(page.accessBusy,false);
    assert.equal(calls.some(call=>call.url.endsWith('/access/apply')),false);
});

test('the external-change lock disables editing and saving while leaving explicit refresh available', () => {
    const {page} = setup(); page.accessSSHStale = true;
    const accessHTML = fs.readFileSync(path.join(__dirname,'../../web/templates/firewall_access.html'),'utf8');
    const fieldsetDisabled = accessHTML.match(/<fieldset :disabled="([^"]+)"/)[1];
    assert.equal(vm.runInNewContext('with (page) { '+fieldsetDisabled+' }',{page}),true);
    for (const method of ['startAccessSave','applyAccess']) {
        const disabled = accessHTML.match(new RegExp('<button[^>]*@click="'+method+'\\(\\)"[^>]*:disabled="([^"]+)"'))[1];
        assert.equal(vm.runInNewContext('with (page) { '+disabled+' }',{page}),true);
    }
    const refreshDisabled = accessHTML.match(/<button[^>]*@click="refreshAccess\(\)"[^>]*:disabled="([^"]+)"/)[1];
    assert.equal(vm.runInNewContext('with (page) { '+refreshDisabled+' }',{page}),false);
});

test('the actual SSH-port-changed handler retires the old SSH draft and rebuilds the saved policy', async () => {
    const {page, state} = setup();
    state.status.ssh_port = 22; page.portStatus = clone(state.status); page.resetAccessRows();
    page.accessCustomPort = '2222'; page.addAccessRow();
    page.accessPreview = {rules:page.accessPayload(),fingerprint:'stale-preview'};
    state.status.ssh_port = 2222; state.status.access_enabled = true;
    state.status.access_rules = [{protocol:'tcp',port:2222,source:'203.0.113.9/32'},{protocol:'tcp',port:9443,source:''}];
    const handler = portsHTML.match(/@ssh-port-changed\.window="([^"]+)"/)?.[1]; assert(handler);
    await vm.runInNewContext('with (page) { ' + handler + ' }', {page});
    assert.equal(page.portStatus.ssh_port,2222); assert.equal(page.accessDirty,false); assert.equal(page.accessPreview,null);
    assert.equal(page.accessRows.some(row=>row.port===22),false,'The old SSH draft must not re-open port 22.');
    const ssh = page.accessRows.filter(row=>row.port===2222);
    assert.equal(ssh.length,1); assert.equal(ssh[0].fixed,true); assert.equal(ssh[0].label,'SSH');
    assert.equal(ssh[0].scope,'specific'); assert.equal(ssh[0].sources,'203.0.113.9/32');
    assert.equal(page.canRemoveAccessRow(ssh[0]),false,'The new active SSH endpoint remains protected.');
    assert.equal(page.accessPayload().some(rule=>rule.port===22),false);
});

test('an SSH transition status-read failure disables the stale policy until an explicit successful refresh', async () => {
    const {page, context} = setup(), before = draft(page), api = context.api;
    page.accessPreview = {rules:page.accessPayload(),fingerprint:'stale-preview'};
    context.api = async()=>{throw Error('status unavailable');};
    const handler = portsHTML.match(/@ssh-port-changed\.window="([^"]+)"/)?.[1]; assert(handler);
    await vm.runInNewContext('with (page) { ' + handler + ' }', {page});
    assert.equal(page.portStatus.access_available,false); assert.equal(page.accessPreview,null);
    assert.deepEqual(clone(page.accessRows),before,'A failed read must not invent replacement policy.');
    context.api = api; await page.refreshAccess();
    assert.equal(page.portStatus.access_available,true); assert.equal(page.accessDirty,false);
});

for (const oldResult of ['success','failure']) {
    test('a late old port-status ' + oldResult + ' cannot overwrite the confirmed SSH endpoint', async () => {
        const {page, context, state, notices} = setup(), old = deferred(), latest = deferred();
        const oldStatus = {...clone(state.status), ssh_port:22}; let reads = 0;
        context.api = () => (++reads === 1 ? old.promise : latest.promise);
        const first = page.fetchPortStatus();
        const handler = portsHTML.match(/@ssh-port-changed\.window="([^"]+)"/)[1];
        const second = vm.runInNewContext('with (page) { ' + handler + ' }', {page});
        latest.resolve({success:true,data:{...clone(state.status),ssh_port:2222}}); await second;
        if (oldResult === 'success') old.resolve({success:true,data:oldStatus}); else old.reject(Error('stale failure'));
        assert.equal(await first,false);
        assert.equal(page.portStatus.ssh_port,2222); assert.equal(page.portsLoading,false);
        assert.equal(page.accessRows.some(row=>row.port===22),false); assert.equal(notices.length,0);
    });
}

test('an older status response cannot re-enable policy editing while an SSH transition read is pending or fails', async () => {
    const {page, context, state} = setup(), old = deferred(), latest = deferred(); let reads = 0;
    context.api = () => (++reads === 1 ? old.promise : latest.promise);
    const first = page.fetchPortStatus();
    const handler = portsHTML.match(/@ssh-port-changed\.window="([^"]+)"/)[1];
    const second = vm.runInNewContext('with (page) { ' + handler + ' }', {page});
    old.resolve({success:true,data:clone(state.status)}); assert.equal(await first,false);
    assert.equal(page.portsLoading,true); assert.equal(page.portStatus.access_available,false);
    latest.reject(Error('current status unavailable')); await second;
    assert.equal(page.portsLoading,false); assert.equal(page.portStatus.access_available,false);
    assert.equal(page.accessPreview,null);
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
    assert.equal(page.accessToken,'pending-token'); assert.equal(page.accessChecked,false); assert.equal(page.accessExpired,false);
    assert.deepEqual([...timers.values()].map(timer => timer.delay).sort((a,b) => a-b),[70000,95000]);
    assert.equal(calls.some(call => call.url.endsWith('/access/confirm')),false);
    await page.confirmAccess(); assert.equal(calls.some(call => call.url.endsWith('/access/confirm')),false);
    page.accessChecked = true; await page.confirmAccess();
    assert.equal(calls.filter(call => call.url.endsWith('/access/confirm')).length,1); assert.equal(page.accessToken,''); assert.equal(timers.size,0);
});

test('rollback refresh restores observed rules and cannot leave an unapplied custom port in the saved policy', async () => {
    const {page, state, timers} = setup(); draft(page); await page.previewAccess(); await page.applyAccess();
    const rollback = [...timers.values()].find(timer => timer.delay === 95000); assert(rollback); assert.equal(page.accessToken,'pending-token');
    state.status.access_enabled = false; state.status.access_rules = [];
    state.status.access_change_state = 'rolled_back';
    rollback.callback(); await settle();
    assert.equal(page.accessToken,''); assert.equal(page.accessChecked,false); assert.equal(page.portStatus.access_enabled,false);
    assert.equal(page.accessDirty,false); assert.equal(page.accessRows.some(row => row.port === 8088),false);
    assert.equal(page.accessExpired,false); assert.equal(page.accessRollbackReady,false); assert.equal(page.accessDeadline,''); assert.equal(timers.size,0);
});

test('the first save action only checks the draft and focuses the review without applying or saving', async () => {
    const {page, calls, confirmations, notices} = setup(), before = draft(page), focus = [];
    page.$nextTick = callback => callback();
    page.$refs = {accessSaveReview:{scrollIntoView:options => focus.push(['scroll',options.block]), focus:options => focus.push(['focus',options.preventScroll])}};
    await page.startAccessSave();
    assert.deepEqual(calls.map(call => call.url),['/firewall/ports/access/preview']);
    assert.deepEqual(clone(page.accessRows),before); assert.equal(page.accessDirty,true); assert.equal(page.accessToken,'');
    assert(page.accessPreview); assert.equal(confirmations.length,0); assert.equal(notices.some(notice => notice[1] === 'success'),false);
    assert.deepEqual(focus,[['scroll','nearest'],['focus',true]]);
});

test('save validation rejects a restricted port without sources and leaves the draft available for correction', async () => {
    const {page, calls} = setup(); draft(page); const row = page.accessRows.find(item => item.port === 8088);
    row.sources = ''; let focused = false; page.focusAccessSaveStage = () => { focused = true; };
    await page.startAccessSave();
    assert.equal(calls.length,0); assert.equal(page.accessError,'firewall.source_required'); assert.equal(page.accessPreview,null);
    assert.equal(focused,false); assert.equal(page.accessDirty,true); assert.equal(row.sources,'');
});

test('a failed save check preserves the draft and server error without entering verification', async () => {
    const {page, context, calls, notices} = setup(), before = draft(page);
    context.api = async (url,options) => { calls.push({url,options}); throw Error('management address could not be preserved'); };
    let focused = false; page.focusAccessSaveStage = () => { focused = true; };
    await page.startAccessSave();
    assert.deepEqual(calls.map(call => call.url),['/firewall/ports/access/preview']); assert.deepEqual(clone(page.accessRows),before);
    assert.equal(page.accessPreview,null); assert.equal(page.accessToken,''); assert.equal(page.accessBusy,false); assert.equal(page.accessDirty,true);
    assert.equal(page.accessError,'management address could not be preserved'); assert.equal(focused,false);
    assert.equal(notices.some(notice => notice[1] === 'success'),false);
});

test('repeated save clicks share one in-flight preview', async () => {
    const {page, context, calls} = setup(), response = deferred(); draft(page);
    context.api = async (url,options) => { calls.push({url,options}); return response.promise; };
    const first = page.startAccessSave(); await page.startAccessSave();
    assert.equal(calls.length,1); assert.equal(page.accessBusy,true);
    response.resolve({success:true,data:{rules:clone(page.accessPayload()),fingerprint:'checked-draft'}}); await first;
    assert.equal(page.accessBusy,false); assert.equal(page.accessPreview.fingerprint,'checked-draft'); assert.equal(page.accessToken,'');
});

test('returning to edit preserves all selected scopes and sources and invalidates the old review', async () => {
    const {page, calls} = setup(), before = draft(page), rows = page.accessRows;
    await page.startAccessSave(); assert(page.accessPreview); const requestCount = calls.length;
    page.editAccessDraft();
    assert.equal(page.accessPreview,null); assert.equal(page.accessRows,rows); assert.deepEqual(clone(page.accessRows),before);
    assert.equal(page.accessDirty,true); assert.equal(calls.length,requestCount);
    await page.applyAccess(); assert.equal(calls.length,requestCount,'an invalidated review cannot be applied');
});

for (const locked of ['accessBusy','portSubmitting','accessToken']) {
    test('returning to edit is blocked by ' + locked, async () => {
        const {page} = setup(); draft(page); await page.startAccessSave(); const review = page.accessPreview;
        page[locked] = locked === 'accessToken' ? 'pending-token' : true;
        page.editAccessDraft(); assert.equal(page.accessPreview,review); assert.equal(page.accessDirty,true);
    });
}

test('cancelled temporary application retains the review and never writes a policy', async () => {
    const {page, context, calls, timers} = setup(); draft(page); await page.startAccessSave(); const review = page.accessPreview;
    context.confirmModal = async () => false; await page.applyAccess();
    assert.equal(page.accessPreview,review); assert.equal(page.accessToken,''); assert.equal(timers.size,0);
    assert.deepEqual(calls.map(call => call.url),['/firewall/ports/access/preview']);
});

test('changing the draft while the apply confirmation is open prevents the outdated review from being applied', async () => {
    const {page, context, calls} = setup(), confirmation = deferred(); draft(page); await page.startAccessSave();
    context.confirmModal = () => confirmation.promise; const pending = page.applyAccess();
    page.accessRows.find(row => row.port === 8088).sources = '192.0.2.8/32'; page.markAccessDirty();
    confirmation.resolve(true); await pending;
    assert.equal(page.accessPreview,null); assert.equal(page.accessDirty,true); assert.equal(page.accessToken,'');
    assert.equal(calls.some(call => call.url.endsWith('/access/apply')),false);
});

test('an uncertain application response retains the unsaved draft and cannot announce a successful save', async () => {
    const {page, context, calls, notices, timers} = setup(), before = draft(page); await page.startAccessSave();
    const originalAPI = context.api;
    context.api = async (url,options) => {
        if (url.endsWith('/access/apply')) { calls.push({url,options}); throw Error('request timed out'); }
        return originalAPI(url,options);
    };
    await page.applyAccess();
    assert.deepEqual(clone(page.accessRows),before); assert.equal(page.accessDirty,true); assert.equal(page.accessPreview,null);
    assert.equal(page.accessToken,''); assert.equal(page.accessBusy,false); assert.equal(timers.size,0);
    assert.equal(page.accessError,'request timed out firewall.access_apply_uncertain');
    assert.equal(calls.some(call => call.url.endsWith('/access/confirm')),false); assert.equal(notices.some(notice => notice[1] === 'success'),false);
});

test('the confirmation deadline expires separately from rollback and keeps the temporary-policy lock', async () => {
    const {page, calls, timers, state} = setup(); draft(page); await page.startAccessSave(); await page.applyAccess();
    const expiry = [...timers.values()].find(timer => timer.delay === 70000); assert(expiry);
    const callCount = calls.length; page.accessChecked = true; state.now += 70000; expiry.callback();
    assert.equal(page.accessExpired,true); assert.equal(page.accessChecked,false); assert.equal(page.accessToken,'pending-token'); assert.equal(page.accessRollbackReady,false);
    assert.equal(calls.length,callCount); assert.equal(page.canRemoveAccessRow(page.accessRows.find(row => row.port === 8088)),false);
    page.accessChecked = true; await page.confirmAccess(); await page.refreshAccess(); await page.checkAccessRollback();
    assert.equal(calls.length,callCount,'expiry must not confirm or refresh temporary state before rollback');
});

test('confirm rechecks the actual deadline even when a background timer has not fired', async () => {
    const {page, calls, state} = setup(); draft(page); await page.startAccessSave(); await page.applyAccess();
    page.accessChecked = true; state.now = Date.parse(page.accessDeadline); await page.confirmAccess();
    assert.equal(calls.some(call => call.url.endsWith('/access/confirm')),false);
    assert.equal(page.accessExpired,true); assert.equal(page.accessChecked,false); assert.equal(page.accessToken,'pending-token'); assert.equal(page.accessRollbackReady,false);
});

for (const deadline of ['invalid',undefined,'2026-10-10T07:59:59Z']) {
    test('a ' + String(deadline) + ' apply deadline cannot become confirmable', async () => {
        const {page, context, calls, timers} = setup(); draft(page); await page.startAccessSave(); const originalAPI = context.api;
        context.api = async (url,options) => { const response = await originalAPI(url,options); if (url.endsWith('/access/apply')) response.data.deadline = deadline; return response; };
        await page.applyAccess(); page.accessChecked = true; await page.confirmAccess();
        assert.equal(page.accessExpired,true); assert.equal(page.accessToken,'pending-token'); assert.equal(page.accessRollbackReady,false);
        assert.equal(calls.some(call => call.url.endsWith('/access/confirm')),false); assert.deepEqual([...timers.values()].map(timer => timer.delay),[95000]);
    });
}

test('failed rollback observation retains its lock and error until an explicit successful status retry', async () => {
    const {page, context, calls, notices, timers, state} = setup(); draft(page); await page.startAccessSave(); await page.applyAccess();
    const rollback = [...timers.values()].find(timer => timer.delay === 95000), originalAPI = context.api; assert(rollback);
    context.api = async (url,options) => { if (url === '/firewall/ports') { calls.push({url,options}); throw Error('server is unreachable'); } return originalAPI(url,options); };
    state.now += 95000; rollback.callback(); await settle();
    assert.equal(page.accessToken,'pending-token'); assert.equal(page.accessExpired,true); assert.equal(page.accessRollbackReady,true); assert.equal(page.accessChecked,false);
    assert.equal(page.accessError,'firewall.access_status_unverified'); assert.equal(page.accessBusy,false); assert.equal(timers.size,2);
    assert.equal(page.portStatus.access_enabled,true,'a failed read must preserve the last observation instead of inventing restored rules');
    assert.equal(notices.some(notice => notice[1] === 'success'),false);
    state.status.access_enabled = false; state.status.access_rules = []; state.status.access_change_state = 'rolled_back'; context.api = originalAPI;
    await page.checkAccessRollback();
    assert.equal(page.accessToken,''); assert.equal(page.accessExpired,false); assert.equal(page.accessRollbackReady,false); assert.equal(page.accessDeadline,'');
    assert.equal(page.accessError,''); assert.equal(page.portStatus.access_enabled,false); assert.equal(page.accessRows.some(row => row.port === 8088),false); assert.equal(timers.size,0);
    assert.equal(calls.some(call => call.url.endsWith('/access/confirm')),false);
});

test('a failed confirmation preserves the server message and pending token without a success notice', async () => {
    const {page, context, calls, notices, timers} = setup(); draft(page); await page.startAccessSave(); await page.applyAccess(); const originalAPI = context.api;
    context.api = async (url,options) => { if (url.endsWith('/access/confirm')) { calls.push({url,options}); throw Error('rules changed; wait for automatic recovery'); } return originalAPI(url,options); };
    page.accessChecked = true; await page.confirmAccess();
    assert.equal(page.accessError,'rules changed; wait for automatic recovery'); assert.equal(page.accessToken,'pending-token'); assert.equal(page.accessExpired,false);
    assert.equal(page.accessBusy,false); assert.equal(timers.size,2); assert.equal(notices.some(notice => notice[1] === 'success'),false);
});

test('repeated confirmation clicks share one pending write and retain the lock until it completes', async () => {
    const {page, context, calls, notices, timers} = setup(), response = deferred(); draft(page); await page.startAccessSave(); await page.applyAccess();
    const originalAPI = context.api;
    context.api = async (url,options) => {
        if (url.endsWith('/access/confirm')) { calls.push({url,options}); return response.promise; }
        return originalAPI(url,options);
    };
    page.accessChecked = true; const pending = page.confirmAccess(); await page.confirmAccess();
    assert.equal(calls.filter(call => call.url.endsWith('/access/confirm')).length,1);
    assert.equal(page.accessBusy,true); assert.equal(page.accessToken,'pending-token'); assert.equal(timers.size,2);
    assert.equal(notices.some(notice => notice[1] === 'success'),false);
    response.resolve({success:true,data:{}}); await pending;
    assert.equal(page.accessBusy,false); assert.equal(page.accessToken,''); assert.equal(timers.size,0);
    assert.equal(notices.filter(notice => notice[0] === 'firewall.access_saved').length,1);
});

test('an unreadable initial status after apply still preserves the temporary token and independent deadlines', async () => {
    const {page, context, calls, notices, timers} = setup(); draft(page); await page.startAccessSave(); const originalAPI = context.api;
    context.api = async (url,options) => {
        if (url === '/firewall/ports') { calls.push({url,options}); throw Error('status unavailable after apply'); }
        return originalAPI(url,options);
    };
    await page.applyAccess();
    assert.equal(page.accessToken,'pending-token'); assert.equal(page.accessChecked,false); assert.equal(page.accessExpired,false); assert.equal(page.accessBusy,false);
    assert.deepEqual([...timers.values()].map(timer => timer.delay).sort((a,b) => a-b),[70000,95000]);
    assert.equal(calls.some(call => call.url.endsWith('/access/confirm')),false); assert.equal(notices.some(notice => notice[1] === 'success'),false);
    assert.equal(page.canRemoveAccessRow(page.accessRows.find(row => row.port === 8088)),false);
});

test('a failed recovery status response cannot release the token or discard the last observed policy', async () => {
    const {page, context, calls, timers} = setup(); draft(page); await page.startAccessSave(); await page.applyAccess();
    const observed = clone(page.portStatus), rows = clone(page.accessRows), rollback = [...timers.values()].find(timer => timer.delay === 95000);
    context.api = async (url,options) => { calls.push({url,options}); return {success:false,message:'status unavailable'}; };
    rollback.callback(); await settle();
    assert.equal(page.accessToken,'pending-token'); assert.equal(page.accessExpired,true); assert.equal(page.accessRollbackReady,true);
    assert.equal(page.accessError,'firewall.access_status_unverified'); assert.equal(page.accessBusy,false); assert.equal(timers.size,2);
    assert.deepEqual(clone(page.portStatus),observed); assert.deepEqual(clone(page.accessRows),rows);
});

test('a successful explicit confirmation clears both timers and all temporary-verification state', async () => {
    const {page, calls, notices, timers} = setup(); draft(page); await page.startAccessSave(); await page.applyAccess();
    assert.equal(timers.size,2); page.accessChecked = true; await page.confirmAccess();
    assert.equal(calls.filter(call => call.url.endsWith('/access/confirm')).length,1);
    assert.equal(page.accessToken,''); assert.equal(page.accessChecked,false); assert.equal(page.accessDeadline,''); assert.equal(page.accessExpired,false); assert.equal(page.accessRollbackReady,false);
    assert.equal(page.accessTimer,null); assert.equal(page.accessExpiryTimer,null); assert.equal(timers.size,0);
    assert(notices.some(notice => notice[0] === 'firewall.access_saved' && notice[1] === 'success'));
});

for (const recoveryState of ['pending','error','unknown',undefined]) {
    test('a readable policy with '+String(recoveryState)+' recovery state cannot release the temporary lock',async()=>{
        const {page,timers,state,notices}=setup();draft(page);await page.startAccessSave();await page.applyAccess();
        state.status.access_change_state=recoveryState;state.status.access_change_error=recoveryState==='error'?'rollback failed; temporary rules still active':'';
        const rollback=[...timers.values()].find(timer=>timer.delay===95000);rollback.callback();await settle();
        assert.equal(page.accessToken,'pending-token');assert.equal(page.accessChangeID,'c'.repeat(32));
        assert.equal(page.accessExpired,true);assert.equal(page.accessRollbackReady,true);assert.equal(page.accessBusy,false);
        assert.equal(page.portStatus.access_enabled,true);assert.equal(page.accessError,state.status.access_change_error||'firewall.access_status_unverified');
        assert.equal(notices.some(notice=>notice[1]==='success'),false);
    });
}

test('a completed recovery belonging to another change cannot unlock this pending policy',async()=>{
    const {page,timers,state}=setup();draft(page);await page.startAccessSave();await page.applyAccess();
    state.status.access_change_id='d'.repeat(32);state.status.access_change_state='rolled_back';
    [...timers.values()].find(timer=>timer.delay===95000).callback();await settle();
    assert.equal(page.accessToken,'pending-token');assert.equal(page.accessChangeID,'c'.repeat(32));assert.equal(page.accessError,'firewall.access_status_unverified');
});

test('the matching confirmed change can release a pending lock after the confirmation response was lost',async()=>{
    const {page,timers,state}=setup();draft(page);await page.startAccessSave();await page.applyAccess();
    state.status.access_change_state='confirmed';
    [...timers.values()].find(timer=>timer.delay===95000).callback();await settle();
    assert.equal(page.accessToken,'');assert.equal(page.accessChangeID,'');assert.equal(page.accessError,'');assert.equal(timers.size,0);
});

test('an apply response without a change identifier cannot use an unrelated successful read as proof of recovery',async()=>{
    const {page,context,timers,state}=setup(),originalAPI=context.api;draft(page);await page.startAccessSave();
    context.api=async(url,options)=>{const response=await originalAPI(url,options);if(url.endsWith('/access/apply'))delete response.data.change_id;return response;};
    await page.applyAccess();assert.equal(page.accessToken,'pending-token');assert.equal(page.accessChangeID,'');assert.equal(page.accessError,'firewall.access_status_unverified');
    state.status.access_change_state='rolled_back';[...timers.values()].find(timer=>timer.delay===95000).callback();await settle();
    assert.equal(page.accessToken,'pending-token');assert.equal(page.accessRollbackReady,true);assert.equal(page.accessError,'firewall.access_status_unverified');
});

test('a confirmed save with failed status read distinguishes saved settings from an unverified observation',async()=>{
    const {page,context,notices}=setup(),originalAPI=context.api;draft(page);await page.startAccessSave();await page.applyAccess();
    context.api=async(url,options)=>{if(url==='/firewall/ports')throw Error('status offline');return originalAPI(url,options);};
    page.accessChecked=true;await page.confirmAccess();
    assert.equal(page.accessToken,'');assert.equal(page.accessChangeID,'');assert.equal(page.accessError,'firewall.access_saved_status_unavailable');
    assert.equal(notices.some(notice=>notice[0]==='firewall.access_saved'),true);
});
