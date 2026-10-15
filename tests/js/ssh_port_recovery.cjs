const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const {test} = require('node:test');
const html = fs.readFileSync(path.join(__dirname, '../../web/templates/ssh_port.html'), 'utf8');
const source = html.match(/<script>([\s\S]*?)<\/script>/)[1];
const id = 'a'.repeat(32);

function setup() {
    const calls = [], events = [], notices = [], copied = [], timers = new Map();
    const state = {port:2111,available:false,pending:true,change_id:id,change_state:'pending'};
    let nextTimer = 0;
    const context = {
        t:key=>key, showToast:(...args)=>notices.push(args), confirmModal:async()=>true,
        navigator:{clipboard:{writeText:async text=>copied.push(text)}}, document:{execCommand:()=>false},
        setTimeout:callback=>{timers.set(++nextTimer,callback);return nextTimer;}, clearTimeout:key=>timers.delete(key),
        api:async(url,options={})=>{
            calls.push({url,options});
            if (options.method === 'POST') throw Error('stop rollback: exit status 5');
            return {success:true,data:{...state}};
        },
    };
    vm.createContext(context); vm.runInContext(source,context);
    const page = context.sshPortManager(); page.$dispatch = event=>events.push(event);
    page.change = {token:'one-time-proof',change_id:id,old_port:22,new_port:2111,deadline:'2030-01-01',verify_command:'server supplied verification command'};
    page.status = {...state}; page.port = 2111; page.cloudReady = true;
    page.timer = context.setTimeout(()=>{});
    return {page,state,context,calls,events,notices,copied,timers};
}

for (const terminal of ['rolled_back','confirmed']) {
    test('confirmation failure retires only a verified matching '+terminal+' change', async()=>{
        const {page,state,calls,events,notices,timers}=setup();
        Object.assign(state,{port:terminal==='confirmed'?2111:22,pending:false,available:true,change_state:terminal});
        await page.confirm();
        assert.equal(page.change,null); assert.equal(page.statusUnknown,false); assert.equal(page.error,'');
        assert.equal(page.port,''); assert.equal(page.cloudReady,false); assert.equal(timers.size,0);
        assert.deepEqual(events,['ssh-port-changed']);
        assert.deepEqual(notices,[[terminal==='confirmed'?'ssh_port.saved':'ssh_port.rolled_back',terminal==='confirmed'?'success':'warning']]);
        assert.deepEqual(calls.map(c=>[c.url,c.options.method]),[['/firewall/ssh-port/confirm','POST'],['/firewall/ssh-port',undefined]]);
        assert.equal(calls[0].options.suppressToast,true); assert.equal(calls[1].options.silent,true);
    });
}

test('a still-valid pending change keeps verification and allows a deliberate retry', async()=>{
    const {page,calls,events}=setup(); await page.confirm();
    assert.equal(page.change.token,'one-time-proof'); assert.equal(page.statusUnknown,false);
    assert.equal(page.error,'stop rollback: exit status 5'); assert.deepEqual(events,[]);
    await page.confirm(); assert.equal(calls.filter(c=>c.options.method==='POST').length,2);
});

test('a positive confirmation response without a verified terminal read cannot announce a saved port', async()=>{
    const {page,context,calls,notices}=setup(),original=context.api;
    context.api=(url,options)=>options?.method?Promise.resolve({success:true,data:{confirmed:true}}):original(url,options);
    await page.confirm(); assert(page.change); assert.equal(page.statusUnknown,true);
    assert.equal(page.error,'ssh_port.status_unverified');
    assert.deepEqual(notices,[['ssh_port.status_unverified','error']]);
    assert(calls.every(c=>!c.options.method),'the successful response is followed only by a read');
});

for (const invalid of ['unknown','error','missing ID','different ID','unexpected port','pending terminal']) {
    test('an unverified '+invalid+' status keeps the old token locked until a later proof', async()=>{
        const {page,state,calls,events,timers}=setup();
        Object.assign(state,{pending:false,available:true,port:22,change_state:'rolled_back'});
        if (invalid==='unknown'||invalid==='error') state.change_state=invalid;
        else if (invalid==='missing ID') delete state.change_id;
        else if (invalid==='different ID') state.change_id='b'.repeat(32);
        else if (invalid==='unexpected port') state.port=3333;
        else state.pending=true;
        await page.confirm(); assert.equal(page.change.token,'one-time-proof'); assert.equal(page.statusUnknown,true);
        assert.equal(events.length,0); assert.equal(timers.size,1); assert(page.error.includes('ssh_port.status_unverified'));
        const before=calls.length; await page.confirm(); assert.equal(calls.length,before,'unknown state must not resend confirmation');
        Object.assign(state,{change_id:id,change_state:'rolled_back',pending:false,port:22}); await page.refresh();
        assert.equal(page.change,null); assert.deepEqual(events,['ssh-port-changed']); assert.equal(timers.size,0);
        assert(calls.slice(before).every(c=>!c.options.method),'recovery refresh is read-only');
    });
}

test('failed or malformed read after confirmation cannot unlock or announce success', async()=>{
    for (const read of [async()=>{throw Error('offline');},async()=>({success:true,data:{port:22}})]) {
        const {page,context,calls,notices}=setup(),original=context.api;
        context.api=(url,options)=>options?.method?original(url,options):read();
        await page.confirm(); assert.equal(page.statusUnknown,true); assert(page.change);
        assert.equal(page.status.available,false); assert.equal(notices.length,1); assert.equal(notices[0][1],'error');
        assert(!calls.some(c=>c.url.endsWith('/ssh-port')&&c.options.method==='POST'));
    }
});

test('concurrent confirmation clicks share one POST and one subsequent status read', async()=>{
    const {page,context,calls}=setup(),original=context.api; let release;
    const pending=new Promise(resolve=>{release=resolve;});
    context.api=async(url,options)=>{if(options?.method){await pending;}return original(url,options);};
    const first=page.confirm(); await page.confirm(); assert.equal(page.busy,true);
    release(); await first; assert.equal(calls.filter(c=>c.options.method==='POST').length,1);
    assert.equal(calls.filter(c=>!c.options.method).length,1); assert.equal(page.busy,false);
});

test('the existing timeout never discards an unverified transaction or posts a mutation', async()=>{
    const {page,state,context,calls,timers}=setup(); page.change=null; page.status={port:22,available:true,pending:false};
    context.api=async(url,options={})=>{calls.push({url,options});return options.method?{success:true,data:{token:'proof',change_id:id,old_port:22,new_port:2111,deadline:'2030-01-01'}}:{success:true,data:{...state,change_state:'unknown'}};};
    await page.begin(); const callback=timers.get(page.timer); assert(callback); await callback();
    assert(page.change); assert.equal(page.statusUnknown,true);
    assert.equal(calls.filter(c=>c.options.method==='POST').length,1,'timeout reads but never confirms');
});

for (const deadline of ['invalid','2000-01-01']) {
    test('a '+deadline+' deadline only reads actual status and never resends an expired token', async()=>{
        const {page,calls,events}=setup(); page.change.deadline=deadline;
        await page.confirm(); assert.equal(page.statusUnknown,true); assert(page.change);
        assert.equal(calls.length,1); assert.equal(calls[0].options.method,undefined); assert.deepEqual(events,[]);
    });
}

test('confirmation expiry disables the button without discarding its receipt or posting', async()=>{
    const {page,state,context,calls,timers}=setup(); page.change=null; page.status={port:22,available:true,pending:false};
    context.api=async(url,options={})=>{calls.push({url,options});return {success:true,data:options.method?{token:'proof',change_id:id,old_port:22,new_port:2111,deadline:'2030-01-01'}:{...state}};};
    await page.begin(); const before=calls.length; timers.get(page.expiryTimer)();
    assert.equal(page.statusUnknown,true); assert(page.change); assert.equal(calls.length,before);
    await page.confirm(); assert.equal(calls.length,before,'the expiry lock cannot resend confirmation');
});

test('copying uses only the displayed verification command and never calls the API', async()=>{
    const {page,copied,calls,context,notices}=setup(); await page.copyVerification();
    assert.deepEqual(copied,['server supplied verification command']); assert.equal(calls.length,0);
    let selected=false; context.navigator.clipboard.writeText=async()=>{throw Error('clipboard denied');};
    page.$refs={sshVerificationCommand:{focus(){},select(){selected=true;}}}; context.document.execCommand=()=>true;
    await page.copyVerification(); assert(selected); assert.equal(calls.length,0);
    context.document.execCommand=()=>false; await page.copyVerification(); assert.equal(page.error,'ssh_port.copy_failed');
    assert.equal(notices.at(-1)[1],'error');
});

test('verification instructions have three semantic steps and no executable login placeholders',()=>{
    assert(!html.includes('USER@SERVER_IP')); assert.match(html,/<ol[^>]*>/);
    for(const key of ['step_connect','step_verify','step_confirm','copy_verification']) assert(html.includes('ssh_port.'+key));
    assert(html.includes('x-show="!!change"')); assert(html.includes(':disabled="busy || statusUnknown || changeExpired()"'));
});
