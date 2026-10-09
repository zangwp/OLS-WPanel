const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const { test } = require('node:test');

const html = fs.readFileSync(path.join(__dirname, '../../web/templates/websites.html'), 'utf8');
const source = [...html.matchAll(/<script[^>]*>([\s\S]*?)<\/script>/g)].map(match => match[1]).join('\n');
const deferred = () => { let resolve, reject; const promise = new Promise((a, b) => { resolve = a; reject = b; }); return { promise, resolve, reject }; };

function setup() {
    const calls = [], notices = [];
    const context = {
        t: (key, values = {}) => key + (values.domain ? ':' + values.domain : ''),
        currentLocale: () => 'en-US', showToast: (...args) => notices.push(args), confirmModal: async () => true,
        api: async (url, options) => { calls.push({url, options}); return {success:true, data:[]}; },
        window: {innerWidth:800, innerHeight:600}, document: {activeElement:null},
    };
    vm.createContext(context); vm.runInContext(source, context);
    const page = context.websiteList();
    page.$nextTick = callback => callback();
    return {page, context, calls, notices};
}

test('more button and popup aria labels interpolate the domain using the actual translation helper', () => {
    const app=fs.readFileSync(path.join(__dirname,'../../web/js/app.js'),'utf8');
    const helper=app.match(/function t\(key[\s\S]*?\n}\r?\n/)[0];
    const expressions=[...html.matchAll(/:aria-label="([^"]*more_actions_for[^"]*)"/g)].map(match=>match[1]);
    assert.equal(expressions.length,2);
    for(const lang of ['zh-CN','en-US']) {
        const messages=JSON.parse(fs.readFileSync(path.join(__dirname,'../../internal/i18n/locales/'+lang+'.json'),'utf8'));
        const context={window:{OLS_WPANEL_I18N:{messages:{'website.more_actions_for':messages.website.more_actions_for}}},site:{domain:'sample.example'},moreSite:{domain:'sample.example'}};
        vm.createContext(context);vm.runInContext(helper,context);
        for(const expression of expressions) {const label=vm.runInContext(expression,context);assert(label.includes('sample.example'));assert(!label.includes('{domain}'));}
    }
});

test('loading and failed reads never become a false empty website result; retry succeeds', async () => {
    const {page, context} = setup();
    const wait = deferred(); context.api = () => wait.promise;
    const request = page.fetchList();
    assert.equal(page.loading, true); assert.equal(page.loaded, false);
    await page.fetchList();
    wait.reject(new Error('offline')); await request;
    assert.equal(page.loaded, false); assert.equal(page.loadError, 'offline'); assert.equal(page.loading, false);
    context.api = async () => ({success:true, data:[]}); await page.fetchList();
    assert.equal(page.loaded, true); assert.equal(page.loadError, '');
});

test('malformed list refresh keeps the last known rows and exposes a retry error', async () => {
    const {page, context} = setup(); const site={id:1,domain:'example.test'};
    page.websites=[site]; page.loaded=true;
    context.api = async () => ({success:true, data:null}); await page.fetchList();
    assert.equal(page.websites[0], site); assert(page.loadError);
});

test('more menu stays inside viewport and keyboard navigation skips hidden or disabled actions', () => {
    const {page, context} = setup(); const focused=[];
    const item = (id, options={}) => ({disabled:false, style:{}, focus(options){assert.equal(options.preventScroll,true);context.document.activeElement=this;focused.push(id);}, ...options});
    const items=[item('pause'),item('restore',{style:{display:'none'}}),item('reinstall',{disabled:true}),item('delete')];
    const menu={getBoundingClientRect:()=>({height:200}),querySelectorAll:()=>items};
    let returned=0; const trigger={isConnected:true,focus:options=>{assert.equal(options.preventScroll,true);returned++;},getBoundingClientRect:()=>({right:790,bottom:590})};
    page.$refs={moreMenu:menu}; page.openMore({currentTarget:trigger}, {id:1,domain:'example.test'});
    assert(page.moreStyle.includes('left:544px')); assert(page.moreStyle.includes('top:388px')); assert.deepEqual(focused,['pause']);
    const key = value => page.handleMoreKey({key:value,currentTarget:menu,preventDefault(){},stopPropagation(){}});
    key('ArrowDown'); assert.equal(focused.at(-1),'delete');
    key('ArrowDown'); assert.equal(focused.at(-1),'pause');
    key('End'); assert.equal(focused.at(-1),'delete');
    key('Escape'); assert.equal(page.moreSite,null); assert.equal(returned,1);
});

test('pause owns the operation lock while confirming; cancellation sends no mutation', async () => {
    const {page, context, calls} = setup(); const site={id:1,status:'active',domain:'example.test'};
    const confirmation=deferred(); let dialogs=0; context.confirmModal=()=>{dialogs++;return confirmation.promise;};
    const first=page.toggleStatus(site); await page.toggleStatus(site); await page.deleteSite(site); await page.fetchList();
    assert.equal(dialogs,1); assert.equal(page.siteBusy(site),true); assert.equal(calls.length,0);
    confirmation.resolve(false); await first;
    assert.equal(site.status,'active'); assert.equal(page.siteBusy(site),false); assert.equal(calls.length,0);
});

test('failed pause retains running state and permits an explicit retry', async () => {
    const {page, context} = setup(); const site={id:1,status:'active',domain:'example.test'};
    context.api=async()=>{throw new Error('failed');}; await page.toggleStatus(site);
    assert.equal(site.status,'active'); assert.equal(page.siteBusy(site),false);
    context.api=async()=>({success:true,data:{}}); await page.toggleStatus(site); assert.equal(site.status,'paused');
});

test('reinstallation requires confirmation and duplicate requests cannot run concurrently', async () => {
    const {page, context} = setup(); const site={id:2,site_type:'wordpress',domain:'example.test'};
    const confirm=deferred(), request=deferred(); let dialogs=0, writes=0;
    context.confirmModal=()=>{dialogs++;return confirm.promise;}; context.api=()=>{writes++;return request.promise;};
    const first=page.reinstallWP(site); await page.reinstallWP(site); assert.equal(dialogs,1); assert.equal(writes,0);
    confirm.resolve(true); await new Promise(resolve=>setImmediate(resolve));
    await page.reinstallWP(site); assert.equal(writes,1);
    request.resolve({success:true,data:{}}); await first; assert.equal(page.siteBusy(site),false); assert.equal(page.reinstallingId,null);
});

test('delete preserves backup warnings and locks the target before usage and confirmation', async () => {
    const {page, context} = setup(); const site={id:3,domain:'backup.test'}; page.websites=[site];
    const usage=deferred(); let dialogs=0, message='', writes=0;
    context.api=async(url, options)=>{if(url.endsWith('backup-usage'))return usage.promise;writes++;return {success:true};};
    context.confirmModal=async text=>{dialogs++;message=text;return false;};
    const first=page.deleteSite(site); await page.deleteSite(site); assert.equal(page.siteBusy(site),true);
    usage.resolve({success:true,data:{db_backup_count:2,file_backup_count:0,auto_backup_enabled:true,cron_jobs:[]}}); await first;
    assert.equal(dialogs,1); assert(message.includes('delete_has_backups_warning')); assert.equal(writes,0); assert.equal(page.websites[0],site); assert.equal(page.siteBusy(site),false);
});
