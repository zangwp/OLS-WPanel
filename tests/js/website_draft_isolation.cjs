const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const {test} = require('node:test');

const template = name => fs.readFileSync(path.join(__dirname, '../../web/templates', name), 'utf8');
const ok = data => ({success:true, data});
const deferred = () => { let resolve, reject; const promise = new Promise((a,b) => { resolve=a; reject=b; }); return {promise,resolve,reject}; };
function setup(name, factory, respond) {
    const html=template(name), calls=[], toasts=[];
    const context={URL, AbortController, TextEncoder, currentLocale:()=> 'en-US', t:key=>key,
        showToast:(...args)=>toasts.push(args), setTimeout(){}, setInterval(){}, clearInterval(){},
        window:{location:{pathname:'/panel/websites/1',search:'',hash:''}}, document:{hidden:false},
        api:async(url,options)=>{ calls.push({url,options}); return respond(url,options); }};
    const script=[...html.matchAll(/<script[^>]*>([\s\S]*?)<\/script>/g)].map(match=>match[1].replace(/{{[\s\S]*?}}/g,'translated')).join('\n');
    vm.createContext(context); vm.runInContext(script,context);
    return {page:context[factory](1),context,calls,toasts,html};
}
const savedSite = () => ({id:1,domain:'site.example',site_type:'wordpress',status:'active',
    litespeed_cache_enabled:false,litespeed_cache_ttl:300,php_version:'8.3',cdn_realip_groups:[{id:1}],
    monitoring_interval:5,log_retention_days:14,ssl_export_enabled:false});
function detail(respond) {
    const f=setup('website_detail.html','websiteDetail',respond);
    f.page.site=savedSite(); Object.assign(f.page,f.page.detailFormValues(f.page.site));
    f.page.loadDetailTab=()=>{}; f.page.scrollDetailAnchor=()=>{};
    return f;
}

test('saving SSL export refreshes saved state without replacing unrelated website drafts or later edits',async()=>{
    const read=deferred();
    const f=detail((url,options)=>options?.method==='PUT'?ok({}):read.promise);
    f.page.lscacheTTL=600; f.page.wpMemoryLimit='256M'; f.page.cdnRealIPGroupIDs=[2,3]; f.page.sslExportEnabled=true;
    const saving=f.page.saveSSLExport();
    await new Promise(resolve=>setImmediate(resolve));
    f.page.logRetentionDays=30;
    read.resolve(ok({...savedSite(),php_version:'8.4',ssl_export_enabled:true,disable_file_editing:true}));
    await saving;
    assert.equal(f.calls.length,2); assert.equal(f.calls[0].options.method,'PUT');
    assert.equal(f.calls[1].url,'/websites/1');
    assert.equal(f.page.lscacheTTL,600); assert.equal(f.page.wpMemoryLimit,'256M');
    assert.deepEqual([...f.page.cdnRealIPGroupIDs],[2,3]); assert.equal(f.page.logRetentionDays,30);
    assert.equal(f.page.phpVersion,'8.4'); assert.equal(f.page.savedDisableFileEditing,true);
    assert.equal(f.page.disableFileEditing,true); assert.equal(f.page.site.ssl_export_enabled,true);
    assert.equal(f.page.sslExportSaving,false);
});

test('first website load hydrates fields and unchanged drafts can follow later persisted changes',async()=>{
    const f=setup('website_detail.html','websiteDetail',async()=>ok({...savedSite(),litespeed_cache_ttl:900}));
    f.page.loadDetailTab=()=>{}; f.page.scrollDetailAnchor=()=>{};
    await f.page.fetchDetail(); assert.equal(f.page.lscacheTTL,900);
    f.context.api=async()=>ok({...savedSite(),litespeed_cache_ttl:1200});
    await f.page.fetchDetail(); assert.equal(f.page.lscacheTTL,1200);
});

test('cron reload preserves other schedule drafts and failed saves retain the submitted schedule',async()=>{
    const jobs=[1,2].map(id=>({id,site_id:1,task_type:'wp_cron',name:'job'+id,cron_expression:'*/5 * * * *',enabled:true}));
    const f=detail(async(_url,options)=>{if(options?.method==='PUT') throw Error('offline'); return ok(jobs);});
    await f.page.loadSiteJobs(); f.page.wpCronJobs[0]._schedule='*/10 * * * *'; f.page.wpCronJobs[1]._schedule='*/30 * * * *';
    await f.page.saveWPCron(f.page.wpCronJobs[0],true);
    assert.equal(f.calls.length,3); assert.equal(f.calls.filter(call=>call.options?.method==='PUT').length,1);
    assert.deepEqual(f.page.wpCronJobs.map(job=>job._schedule),['*/10 * * * *','*/30 * * * *']);
    assert.equal(f.page.wpCronBusy,false);
});

test('cron successful save keeps a newer schedule edit while reloading server job state',async()=>{
    const write=deferred(), job={id:1,site_id:1,task_type:'wp_cron',name:'job',cron_expression:'*/5 * * * *',enabled:true};
    const f=detail(async(_url,options)=>options?.method==='PUT'?write.promise:ok([{...job,cron_expression:'*/10 * * * *'}]));
    f.page.wpCronJobs=[{...job,_schedule:'*/10 * * * *'}];
    const saving=f.page.saveWPCron(f.page.wpCronJobs[0],false);
    f.page.wpCronJobs[0]._schedule='*/30 * * * *'; await f.page.saveWPCron(f.page.wpCronJobs[0],true);
    assert.equal(f.calls.length,1); assert.equal(f.calls[0].options.body.cron_expression,'*/10 * * * *');
    write.resolve(ok({})); await saving;
    assert.equal(f.page.wpCronJobs[0]._schedule,'*/30 * * * *'); assert.equal(f.calls.length,2);
});

test('security refresh preserves maintenance form and password drafts without another secret read',async()=>{
    const f=detail(async url=>ok(url.endsWith('/password')?{password:'saved-secret'}:{state:'locked',enabled:true,minutes:5}));
    f.page.detailTab='security'; f.page.refreshSiteSecurityAfterChange=()=>{};
    await f.page.loadMaintenance(true);
    f.page.maintenanceEnabled=false; f.page.maintenanceMinutes=10; f.page.maintenancePasswordInput='unsaved-secret';
    await f.page.loadMaintenance(true);
    assert.equal(f.page.maintenanceEnabled,false); assert.equal(f.page.maintenanceMinutes,10);
    assert.equal(f.page.maintenancePasswordInput,'unsaved-secret'); assert.equal(f.calls.length,3);
    assert.equal(f.calls.filter(call=>call.url.endsWith('/password')).length,1);
});

test('a late maintenance password read cannot replace a password typed during the request',async()=>{
    const read=deferred(), f=detail(()=>read.promise); f.page.detailTab='security';
    const pending=f.page.loadMaintenancePassword(); f.page.maintenancePasswordInput='new-local-secret';
    read.resolve(ok({password:'old-server-secret'})); await pending;
    assert.equal(f.page.maintenancePasswordInput,'new-local-secret'); assert.equal(f.calls.length,1);
});

test('AI access status reload keeps tool choices and an active action busy while coalescing duplicate reads',async()=>{
    const read=deferred(), f=detail(()=>read.promise);
    f.page.aiAccess.loaded=true; f.page.aiAccess.installWPCLI=false; f.page.aiAccess.installNodeJS=true; f.page.aiAccess.busy=true;
    const pending=f.page.fetchAIDevelopment(); await f.page.fetchAIDevelopment();
    assert.equal(f.calls.length,1);
    read.resolve(ok({status:'disabled',enabled:false,busy:false,tools:[]})); await pending;
    assert.equal(f.page.aiAccess.installWPCLI,false); assert.equal(f.page.aiAccess.installNodeJS,true);
    assert.equal(f.page.aiAccess.busy,true); assert.equal(f.page.aiAccess.loading,false);
});

const account='a'.repeat(32), otherAccount='b'.repeat(32);
const cfConfig = () => ({site_id:1,hostname:'site.example',scope:'shared_web_bans',enabled:false,account_id:account,
    token_configured:true,zone_id:'',rule_id:'',active_ip_count_known:true,active_ip_count:0,sync_status:'disabled'});
test('Cloudflare refresh updates observed status but keeps binding drafts and never resubmits them',async()=>{
    const read=deferred(), f=setup('site_cloudflare_security.html','siteCloudflareSecurity',()=>read.promise);
    f.page.site={id:1,domain:'site.example'}; f.page.applyCloudflareConfig(cfConfig(),1);
    f.page.cfForm={enabled:true,account_id:otherAccount}; f.page.cfToken='unsaved-token';
    const pending=f.page.loadCloudflare(); await f.page.loadCloudflare();
    assert.equal(f.calls.length,1); assert.equal(f.calls[0].options.method,'GET');
    read.resolve(ok({...cfConfig(),active_ip_count:4})); await pending;
    assert.equal(f.page.cfForm.enabled,true); assert.equal(f.page.cfForm.account_id,otherAccount);
    assert.equal(f.page.cfToken,'unsaved-token'); assert.equal(f.page.cfConfig.active_ip_count,4);
    assert.equal(f.page.canSyncCloudflare(),false); assert.equal(f.page.cfBusy,'');
});

test('anomaly check preserves unsaved configuration while refreshing evidence and retaining same-resource locking',async()=>{
    const read=deferred(), f=setup('wp_anomaly_panel.html','wpAnomalyMonitor',()=>read.promise);
    f.page.state={enabled:true,threshold:5}; f.page.enabled=false; f.page.threshold=12;
    const pending=f.page.check(); await f.page.save(); await f.page.check();
    assert.equal(f.calls.length,1); assert.equal(f.page.busy,true); assert.equal(f.page.action,'check');
    read.resolve(ok({enabled:true,threshold:5,last_success:123})); await pending;
    assert.equal(f.page.enabled,false); assert.equal(f.page.threshold,12); assert.equal(f.page.state.last_success,123);
    assert.equal(f.page.busy,false); assert.equal(f.page.action,'');
});

test('anomaly saving reports saving without replacing the form on failure',async()=>{
    const write=deferred(), f=setup('wp_anomaly_panel.html','wpAnomalyMonitor',()=>write.promise);
    f.page.state={enabled:true,threshold:5}; f.page.enabled=false; f.page.threshold=12;
    const pending=f.page.save(); assert.equal(f.page.action,'save');
    const label=f.html.match(/<p x-show="busy"[^>]*x-text="([^"]+)"/)[1];
    assert.equal(vm.runInNewContext(label,{...f.page,t:key=>key}),'common.saving');
    write.reject(Error('offline')); await pending;
    assert.equal(f.page.enabled,false); assert.equal(f.page.threshold,12); assert.equal(f.page.busy,false);
    assert.equal(f.calls.length,1);
});

test('fleet update-check toggles serialize one website while allowing another website to proceed',async()=>{
    const one=deferred(), two=deferred();
    const sites=[1,2].map(id=>({id,domain:'site'+id+'.example',site_type:'wordpress',update_checks_disabled:false,health:{level:'healthy'},inventory:null}));
    const f=setup('wp_fleet_overview.html','wpFleetOverview',(url,options)=>options?.method==='PUT'?(url.includes('/1/')?one.promise:two.promise):ok({sites,counts:{}}));
    f.page.overview={sites,counts:{}};
    const first=f.page.toggleUpdateChecks(sites[0]); await f.page.toggleUpdateChecks(sites[0]);
    const disabled=f.html.match(/@click.stop.prevent="toggleUpdateChecks\(site\)" :disabled="([^"]+)"/)[1];
    assert.equal(vm.runInNewContext(disabled,{...f.page,site:sites[0]}),true);
    assert.equal(vm.runInNewContext(disabled,{...f.page,site:sites[1]}),false);
    const second=f.page.toggleUpdateChecks(sites[1]); assert.equal(f.calls.length,2);
    one.resolve(ok({enabled:false})); await first;
    assert.equal(f.page.updateCheckSavingSiteIDs[1],undefined); assert.equal(f.page.updateCheckSavingSiteIDs[2],true);
    two.resolve(ok({enabled:false})); await second;
    assert.equal(f.calls.filter(call=>call.options?.method==='PUT').length,2);
    assert.equal(f.calls.filter(call=>call.url==='/wp-fleet/overview').length,2);
    assert.equal(f.page.disabledUpdateCheckCount(),2); assert.equal(Object.keys(f.page.updateCheckSavingSiteIDs).length,0);
});

test('a successful fleet toggle updates the current row even if another refresh replaced its original object',async()=>{
    const write=deferred(), original={id:1,site_type:'wordpress',update_checks_disabled:false,health:{level:'healthy'},inventory:null};
    const f=setup('wp_fleet_overview.html','wpFleetOverview',(_url,options)=>{if(options?.method==='PUT') return write.promise; throw Error('reload failed');});
    f.page.overview={sites:[original],counts:{}};
    const pending=f.page.toggleUpdateChecks(original), replacement={...original};
    f.page.overview={sites:[replacement],counts:{}};
    write.resolve(ok({enabled:false})); await pending;
    assert.equal(replacement.update_checks_disabled,true); assert.equal(f.page.disabledUpdateCheckCount(),1);
    assert.equal(f.page.staleOverview,true); assert.equal(f.calls.length,2);
});

test('core update backup choice is disabled for its own immutable submission while cancel remains available',async()=>{
    const write=deferred(), f=setup('wp_core_update_panel.html','wpCoreUpdatePanel',()=>write.promise);
    f.context.confirmModal=async()=>true; f.page.siteID=1; f.page.databaseBackupMode='reuse';
    f.page.preview={current_version:'6.9',target_version:'7.0',confirmation_token:'opaque'}; f.page.schedulePoll=()=>{};
    const pending=f.page.confirmUpdate(); await new Promise(resolve=>setImmediate(resolve)); await f.page.confirmUpdate();
    const inputs=[...f.html.matchAll(/<input\b[^>]*x-model="databaseBackupMode"[^>]*>/g)].map(match=>match[0]);
    assert.equal(inputs.length,2); for(const input of inputs) assert.match(input,/:disabled="confirming"/);
    assert.equal(f.page.confirming,true); assert.equal(f.calls.length,1);
    assert.equal(f.calls[0].options.body.database_backup_mode,'reuse');
    assert.match(f.html,/@click="confirming \? cancelPreparation\(\) : discardPreview\(\)" class=/);
    write.resolve(ok({task_id:'task1',site_id:1,component_type:'core',task_kind:'update',status:'queued'})); await pending;
    assert.equal(f.page.confirming,false); assert.equal(f.page.task.task_id,'task1');
});

test('plugin batch selection stays fixed while submitting and is retained when the submission fails',async()=>{
    const write=deferred(), f=setup('wp_inventory_panel.html','wpInventoryPanel',()=>write.promise);
    f.page.siteID=1; f.page.pluginBatch.selected.add('plugin-one');
    const pending=f.page.submitPluginBatch(); await f.page.submitPluginBatch();
    f.page.togglePluginBatchItem('plugin-two'); f.page.pluginBatchSelectClear(); f.page.pluginBatchSelectAll();
    assert.deepEqual([...f.page.pluginBatch.selected],['plugin-one']); assert.equal(f.calls.length,1);
    assert.deepEqual([...f.calls[0].options.body.component_keys],['plugin-one']);
    for(const field of ['pluginUpdate.riskAccepted','pluginUpdate.databaseBackupMode']) {
        for(const tag of [...f.html.matchAll(/<input\b[^>]*>/g)].map(match=>match[0]).filter(tag=>tag.includes('x-model="'+field+'"'))) assert.match(tag,/:disabled="pluginUpdate.submitting"/);
    }
    assert.match(f.html,/@change="togglePluginBatchItem\(item.key\)"/);
    assert.match(f.html,/:checked="pluginBatch.selected.has\(item.key\)" :disabled="pluginBatch.submitting"/);
    write.reject(Error('offline')); await pending;
    assert.equal(f.page.pluginBatch.submitting,false); assert.deepEqual([...f.page.pluginBatch.selected],['plugin-one']);
});

test('WordPress authorization saving does not show an unrelated login action as authorizing',async()=>{
    const write=deferred(), f=setup('wordpress_access.html','wordpressPanelAccess',()=>write.promise);
    f.page.site={id:1,site_type:'wordpress',domain:'site.example'};
    f.page.status={installed:true,sso_enabled:false,administrators:[]}; f.page.settingsPassword='secret';
    const pending=f.page.save(); await f.page.revoke();
    assert.equal(f.calls.length,1); assert.equal(f.page.busyAction,'save');
    const labels=[...f.html.matchAll(/x-text="([^"]*busyAction[^\"]*)"/g)].map(match=>vm.runInNewContext(match[1],{...f.page,t:key=>key}));
    assert(labels.includes('common.saving')); assert(!labels.includes('wp_access.authorizing'));
    write.reject(Error('offline')); await pending;
    assert.equal(f.page.busyAction,''); assert.equal(f.page.busy,false);
    assert.equal(f.page.settingsPassword,'');
});

test('website creation disables only its own form for the existing single submitted snapshot',async()=>{
    const write=deferred(), f=setup('website_new.html','createWebsite',()=>write.promise);
    assert.match(f.html,/<form @submit.prevent="submit">\s*<fieldset :disabled="loading"/);
    assert.match(f.html,/<\/fieldset>\s*<\/form>/);
    f.page.domain='site.example'; const pending=f.page.submit(); await f.page.submit();
    assert.equal(f.page.loading,true); assert.equal(f.calls.length,1);
    write.reject(Error('offline')); await pending;
    assert.equal(f.page.loading,false); assert.equal(f.page.domain,'site.example');
});
