const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const {test} = require('node:test');
const source = fs.readFileSync(path.join(__dirname,'../../web/templates/ssh_port.html'),'utf8').match(/<script>([\s\S]*?)<\/script>/)[1];

function setup() {
    const calls=[], events=[], timers=[];
    const state={port:2222,available:true,pending:false};
    const context={t:key=>key,showToast:()=>{},confirmModal:async()=>true,clearTimeout:()=>{},setTimeout:callback=>{timers.push(callback);return timers.length;},
        api:async(url,options={})=>{
            calls.push({url,options});
            if(url.endsWith('/confirm'))return {success:true};
            if(options.method==='POST')return {success:true,data:{token:'proof',old_port:2222,new_port:3333}};
            return {success:true,data:{...state}};
        }};
    vm.createContext(context); vm.runInContext(source,context);
    const page=context.sshPortManager(); page.$dispatch=event=>events.push(event);
    return {page,state,calls,events,timers,context};
}

test('refreshing SSH status notifies the parent with a read-only observation event', async()=>{
    const {page,calls,events}=setup(); await page.refresh();
    assert.equal(page.status.port,2222); assert.deepEqual(events,['ssh-port-observed']);
    assert.deepEqual(calls.map(call=>[call.url,call.options.method]),[['/firewall/ssh-port',undefined]]);
});

test('pending or failed SSH status checks do not announce an external port change', async()=>{
    const {page,state,events,context}=setup(); state.pending=true; await page.refresh();
    assert.deepEqual(events,[]);
    state.pending=false; page.change={token:'pending'}; await page.refresh(); assert.deepEqual(events,[]);
    page.change=null; context.api=async()=>{throw Error('read failed');}; await page.refresh();
    assert.equal(page.status.available,false); assert.equal(page.error,'read failed'); assert.deepEqual(events,[]);
});

test('panel-managed confirmation emits one authoritative reload without a second observation event', async()=>{
    const {page,state,events}=setup();
    page.change={token:'proof'}; state.port=3333; await page.confirm();
    assert.equal(page.change,null); assert.equal(page.status.port,3333);
    assert.deepEqual(events,['ssh-port-changed']);
});

test('panel-managed timeout emits one authoritative reload and keeps the existing rollback timer', async()=>{
    const {page,events,timers}=setup();
    page.status={port:2222,available:true}; page.port=3333; page.cloudReady=true; await page.begin();
    assert.equal(timers.length,1); assert.equal(page.change.new_port,3333);
    await timers[0]();
    assert.equal(page.change,null); assert.deepEqual(events,['ssh-port-changed']);
});
