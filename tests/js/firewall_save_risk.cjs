const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const {test} = require('node:test');
const controller = fs.readFileSync(path.join(__dirname, '../../web/templates/firewall_controller.html'), 'utf8').match(/<script>([\s\S]*?)<\/script>/)[1];
const sshTemplate = fs.readFileSync(path.join(__dirname, '../../web/templates/ssh_port.html'), 'utf8');
const accessTemplate = fs.readFileSync(path.join(__dirname, '../../web/templates/firewall_access.html'), 'utf8');
const sshController = sshTemplate.match(/<script>([\s\S]*?)<\/script>/)[1];
const clone = value => JSON.parse(JSON.stringify(value));

function setup({requiresConfirmation = false, applyResult} = {}) {
    const calls = [], dialogs = [], notices = [], timers = new Map(); let timerID = 0;
    const state = {status:{access_available:true, access_enabled:true, ssh_port:2222, panel_port:9443, current_management_ip:'203.0.113.9', listeners:[], rules:[], access_rules:[{protocol:'tcp',port:2222,source:''},{protocol:'tcp',port:9443,source:''},{protocol:'tcp',port:80,source:''},{protocol:'tcp',port:443,source:''}]}};
    const context = {
        t:key => key, showToast:(...args) => notices.push(args),
        confirmModal:async message => { dialogs.push(message); return true; },
        setTimeout(callback,delay) { const id = ++timerID; timers.set(id,{callback,delay}); return id; },
        clearTimeout:id => timers.delete(id),
        api:async (url,options = {}) => {
            calls.push({url,options});
            if (url.endsWith('/access/preview')) return {success:true,data:{rules:clone(options.body.rules), fingerprint:'validated-draft', requires_confirmation:requiresConfirmation, requires_ssh_validation:false}};
            if (url.endsWith('/access/apply')) {
                state.status.access_rules = clone(options.body.rules);
                return {success:true,data:applyResult || (requiresConfirmation ? {requires_confirmation:true,requires_ssh_validation:false,saved:false,confirmation_token:'temporary-token',change_id:'c'.repeat(32),deadline:'2030-01-01'} : {requires_confirmation:false,requires_ssh_validation:false,saved:true})};
            }
            if (url === '/firewall/ports') return {success:true,data:clone(state.status)};
            throw Error('unexpected API: '+url);
        },
    };
    vm.createContext(context); vm.runInContext(controller,context);
    const page = context.firewallManager('ports'); page.portStatus = clone(state.status); page.resetAccessRows();
    return {page,context,calls,dialogs,notices,timers,state};
}

test('ordinary custom port changes save from one click without SSH validation or confirmation timers', async () => {
    const {page,calls,dialogs,notices,timers} = setup();
    page.accessCustomPort = '8088'; page.addAccessRow();
    await page.startAccessSave();
    assert.deepEqual(calls.map(call => call.url),['/firewall/ports/access/preview','/firewall/ports/access/apply','/firewall/ports']);
    assert.equal(dialogs.length,0); assert.equal(timers.size,0); assert.equal(page.accessToken,'');
    assert.equal(page.accessDirty,false); assert.equal(page.accessPreview,null); assert.equal(page.accessSSHValidation,false);
    assert(page.accessPayload().some(rule => rule.port===8088));
    assert(notices.some(notice => notice[0]==='firewall.access_saved' && notice[1]==='success'));
});

test('a managed custom listener rule can be removed and reappears only as a closed observation after saving', async () => {
    const {page,state,calls} = setup();
    state.status.listeners=[{protocol:'tcp',port:8088,process:'custom-app',bind_scope:'network'}];
    state.status.access_rules.push({protocol:'tcp',port:8088,source:''});
    page.portStatus=clone(state.status); page.resetAccessRows();
    const row=page.accessRows.find(row=>row.port===8088);
    assert.equal(row.listening,true); assert.equal(row.custom,true); assert.equal(page.canRemoveAccessRow(row),true);
    page.removeAccessRow(row); assert(!page.accessRows.some(row=>row.port===8088)); assert.equal(calls.length,0);
    await page.startAccessSave();
    assert(!state.status.access_rules.some(rule=>rule.port===8088),'managed inbound allowance was removed');
    const observed=page.accessRows.find(row=>row.port===8088);
    assert(observed); assert.equal(observed.scope,'closed'); assert.equal(observed.listening,true); assert.equal(observed.custom,false);
    assert(!page.accessPayload().some(rule=>rule.port===8088),'live listener observation must not reopen its port');
    assert(!calls.some(call=>call.options.method==='DELETE'),'custom access changes never delete independent legacy rules or stop a service');
});

test('ordinary saves retain saved outcome when only the following status read fails', async () => {
    const {page,context,notices,timers} = setup(), api = context.api;
    context.api = (url,options) => { if(url==='/firewall/ports')throw Error('read unavailable'); return api(url,options); };
    page.accessCustomPort = '8088'; page.addAccessRow(); await page.startAccessSave();
    assert.equal(page.accessToken,''); assert.equal(timers.size,0); assert.equal(page.accessDirty,false);
    assert.equal(page.accessError,'firewall.access_saved_status_unavailable');
    assert(notices.some(notice => notice[0]==='firewall.access_saved' && notice[1]==='success'));
});

test('first strict policy or narrowed management access still requires review and explicit panel confirmation', async () => {
    const {page,calls,dialogs,notices,timers} = setup({requiresConfirmation:true});
    page.accessCustomPort = '8088'; page.addAccessRow(); await page.startAccessSave();
    assert.deepEqual(calls.map(call => call.url),['/firewall/ports/access/preview']);
    assert.equal(page.accessNeedsConfirmation(),true); assert.equal(page.accessReviewHelp(),'firewall.access_management_review');
    await page.applyAccess();
    assert.equal(dialogs.length,1); assert.equal(page.accessToken,'temporary-token'); assert.equal(page.accessSSHValidation,false);
    assert.equal(timers.size,2); assert(!calls.some(call => call.url.endsWith('/confirm')));
    assert(!notices.some(notice => notice[1]==='success'));
});

for (const requiresConfirmation of [undefined,null,0,'false',true]) {
    test('unknown confirmation flag '+String(requiresConfirmation)+' retains guarded review', async () => {
        const {page,calls} = setup();
        page.accessPreview = {requires_confirmation:requiresConfirmation,rules:page.accessPayload(),fingerprint:'review'};
        assert.equal(page.accessNeedsConfirmation(),true);
        assert.equal(page.accessReviewHelp(),'firewall.access_management_review');
        assert.equal(calls.length,0);
    });
}

for(const result of [
    {requires_confirmation:false,saved:false},
    {saved:true},
    {requires_confirmation:false,saved:true,confirmation_token:'contradictory'},
    {requires_confirmation:true,saved:true,confirmation_token:'contradictory'},
    {},
]) {
    test('an incomplete or contradictory immediate save response cannot announce success '+JSON.stringify(result), async () => {
        const {page,notices,timers} = setup({applyResult:result});
        page.accessCustomPort='8088'; page.addAccessRow(); await page.startAccessSave();
        assert.equal(page.accessDirty,true); assert.equal(page.accessToken,''); assert.equal(timers.size,0);
        assert(!notices.some(notice=>notice[1]==='success')); assert(page.accessError);
    });
}

test('removed mail shortcuts leave existing inbound mail rules as ordinary user-managed ports', async () => {
    for(const token of ['access_mail_title','access_mail_help','accessMailPresets','addMailAccessRow']) {
        assert(!accessTemplate.includes(token), 'removed shortcut remains in the template: '+token);
        assert(!controller.includes(token), 'removed shortcut remains in the controller: '+token);
    }
    const {page,state,calls} = setup();
    for(const port of [25,465,587]) state.status.access_rules.push({protocol:'tcp',port,source:'198.51.100.5/32'});
    page.portStatus=clone(state.status); page.resetAccessRows();
    for(const port of [25,465,587]) {
        const row=page.accessRows.find(row=>row.key==='tcp:'+port);
        assert(row); assert.equal(row.scope,'specific'); assert.equal(row.sources,'198.51.100.5/32');
        assert.equal(page.canRemoveAccessRow(row),true);
        assert(page.accessPayload().some(rule=>rule.port===port && rule.source==='198.51.100.5/32'));
    }
    assert.equal(calls.length,0,'rendering the simplified UI must not alter any saved rule');
    page.accessCustomPort='8088'; page.addAccessRow(); await page.startAccessSave();
    for(const port of [25,465,587]) assert(state.status.access_rules.some(rule=>rule.port===port && rule.source==='198.51.100.5/32'),'ordinary save preserves existing inbound mail rule '+port);
});

test('SSH port entry is editable before access policy application while actual changes keep validation', async () => {
    const input=sshTemplate.match(/<input id="ssh-new-port"[^>]*>/)[0];
    const disabled=input.match(/:disabled="([^"]+)"/)[1];
    assert(!disabled.includes('status.available'));
    assert.equal(vm.runInNewContext(disabled,{busy:false,status:{available:false,pending:false}}),false);
    assert.equal(vm.runInNewContext(disabled,{busy:false,status:{available:true,pending:true}}),true);
    const calls=[], context={t:key=>key,confirmModal:async()=>true,showToast:()=>{},clearTimeout:()=>{},setTimeout:()=>1,
        api:async(url,options={})=>{calls.push({url,options}); if(options.method==='POST')return {success:true,data:{token:'ssh-token',new_port:3333,old_port:2222,deadline:'2030-01-01',verify_command:'new SSH session proof'}}; return {success:true,data:{available:true,pending:false,port:2222}};}};
    vm.createContext(context); vm.runInContext(sshController,context); const ssh=context.sshPortManager(); ssh.$dispatch=()=>{};
    ssh.status={available:false,pending:false,port:2222}; ssh.port=3333; ssh.cloudReady=true; await ssh.begin();
    assert.equal(calls.length,0,'unavailable status allows editing but cannot issue a change');
    await ssh.refresh(); await ssh.begin(); assert.equal(ssh.change.new_port,3333);
    assert(ssh.change.verify_command); assert(!calls.some(call=>call.url.endsWith('/confirm')),'actual SSH migration never confirms itself');
});

test('SSH migration rechecks the exact port after confirmation and refuses concurrent starts', async () => {
    let resolve; const dialog = new Promise(done=>{resolve=done;}); const calls=[];
    const context={t:key=>key,confirmModal:()=>dialog,showToast:()=>{},clearTimeout:()=>{},setTimeout:()=>1,
        api:async(url,options)=>{calls.push({url,options});return {success:true,data:{token:'should-not-run'}};}};
    vm.createContext(context); vm.runInContext(sshController,context); const ssh=context.sshPortManager();
    ssh.status={available:true,pending:false,port:2222}; ssh.cloudReady=true; ssh.port=3333;
    const first=ssh.begin(); await ssh.begin(); assert.equal(ssh.busy,true); ssh.port=4444; resolve(true); await first;
    assert.equal(calls.length,0); assert.equal(ssh.busy,false); assert.equal(ssh.change,null);
});
