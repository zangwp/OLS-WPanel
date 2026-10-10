const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const { test } = require('node:test');

const html=fs.readFileSync(path.join(__dirname,'../../web/templates/website_detail.html'),'utf8');
const source=[...html.matchAll(/<script[^>]*>([\s\S]*?)<\/script>/g)].map(match=>match[1].replace(/{{[\s\S]*?}}/g,'translated')).join('\n');
const deferred=()=>{let resolve,reject;const promise=new Promise((a,b)=>{resolve=a;reject=b;});return {promise,resolve,reject};};
const site=()=>({id:1,site_type:'wordpress',litespeed_cache_enabled:false,litespeed_cache_ttl:300,disable_wp_updates:false,disable_file_editing:true,xmlrpc_enabled:false,disable_application_passwords:true,wp_debug_enabled:false,wp_debug_display:false,wp_post_revisions:-1,wp_memory_limit:'',file_lock_enabled:false});
const status=checks=>({success:true,data:{site_id:1,checked_at:'2026-10-09T08:00:00Z',checks}});

function setup() {
    const calls=[],notices=[];
    const context={t:key=>key,currentLocale:()=> 'en-US',showToast:(...args)=>notices.push(args),window:{location:{pathname:'/panel/websites/1',search:'',hash:''},history:{replaceState(){}},addEventListener(){}},api:async(url,options)=>{calls.push({url,options});return status([]);}};
    vm.createContext(context);vm.runInContext(source,context);
    const page=context.websiteDetail();page.site=site();page.detailTab='overview';
    return {page,context,calls,notices};
}

test('monitoring save records the sent snapshot and preserves later edits without another write',async()=>{
    const {page,context,calls,notices}=setup(),saving=deferred();
    page.site.monitoring_enabled=false;page.site.monitoring_interval=5;page.monitoringEnabled=true;page.monitoringInterval=5;
    page.refreshSiteSecurityAfterChange=()=>{};
    context.api=async(url,options)=>{calls.push({url,options});return saving.promise;};
    const pending=page.saveMonitoring();page.monitoringEnabled=false;page.monitoringInterval=10;await page.saveMonitoring();
    assert.equal(calls.length,1);assert.equal(calls[0].options.body.enabled,true);assert.equal(calls[0].options.body.interval,5);
    saving.resolve({success:true,data:{}});await pending;
    assert.equal(page.site.monitoring_enabled,true);assert.equal(page.site.monitoring_interval,5);
    assert.equal(page.monitoringEnabled,false);assert.equal(page.monitoringInterval,10);assert.equal(page.monitoringSaving,false);
    assert.equal(notices.filter(n=>n[0]==='website.monitoring_saved').length,1);
});

test('failed or stale monitoring save cannot replace observed settings or claim success',async()=>{
    const {page,context,notices}=setup();page.site.monitoring_enabled=false;page.site.monitoring_interval=5;
    page.monitoringEnabled=true;page.monitoringInterval=10;
    context.api=async()=>{throw Error('monitoring not saved');};await page.saveMonitoring();
    assert.equal(page.site.monitoring_enabled,false);assert.equal(page.site.monitoring_interval,5);assert.equal(page.monitoringSaving,false);
    assert.equal(notices.some(n=>n[0]==='website.monitoring_saved'),false);
    const saving=deferred();context.api=()=>saving.promise;const pending=page.saveMonitoring();
    page.site={id:2,monitoring_enabled:false,monitoring_interval:15};saving.resolve({success:true,data:{}});await pending;
    assert.equal(page.site.monitoring_enabled,false);assert.equal(page.site.monitoring_interval,15);assert.equal(page.monitoringSaving,false);
    assert.equal(notices.some(n=>n[0]==='website.monitoring_saved'),false);
});

test('unknown and configured checks never claim verified protection; only reliable true evidence is green', () => {
    const {page}=setup(); assert.equal(page.siteSecurityClass('https'),'badge-info');
    page.securityStatus={checks:[{key:'https',state:'configured',configured:true,effective:null},{key:'file_lock',state:'effective',effective:null},null,{key:'xmlrpc',state:'effective',effective:true}]};
    assert.equal(page.siteSecurityStateText('https'),'website.security_state_configured');assert.equal(page.siteSecurityClass('https'),'badge-warning');
    assert.equal(page.siteSecurityStateText('file_lock'),'website.security_state_unknown');assert.equal(page.siteSecurityClass('xmlrpc'),'badge-success');
    assert.equal(page.siteSecurityStateText('missing'),'website.security_state_unknown');
});

test('failed refresh removes previous positive claims and successful retry establishes a fresh observation', async () => {
    const {page,context}=setup(); context.api=async()=>status([{key:'https',state:'effective',effective:true}]);await page.fetchSiteSecurityStatus();
    assert.equal(page.siteSecurityClass('https'),'badge-success');
    context.api=async()=>{throw new Error('offline');};await page.fetchSiteSecurityStatus();
    assert.equal(page.securityStatus,null);assert.equal(page.siteSecurityStateText('https'),'website.security_state_error');assert.notEqual(page.siteSecurityClass('https'),'badge-success');
    context.api=async()=>status([{key:'https',state:'disabled',effective:false}]);await page.fetchSiteSecurityStatus();assert.equal(page.securityStatusError,'');assert.equal(page.siteSecurityStateText('https'),'website.security_state_disabled');
});

test('wrong-site and malformed responses fail safely, including malformed individual entries', async () => {
    const {page,context}=setup();
    for(const data of [null,{site_id:2,checks:[]},{site_id:1,checks:{}}]){context.api=async()=>({success:true,data});await page.fetchSiteSecurityStatus();assert(page.securityStatusError);assert.equal(page.securityStatus,null);}
    context.api=async()=>status([null,{key:'https',state:'invented',effective:true}]);await page.fetchSiteSecurityStatus();assert.equal(page.siteSecurityStateText('https'),'website.security_state_unknown');
});

test('checks share a loading guard and cannot show the previous success while checking', async () => {
    const {page,context}=setup();const wait=deferred();let reads=0;context.api=()=>{reads++;return wait.promise;};
    page.securityStatus={checks:[{key:'https',state:'effective',effective:true}]};
    const first=page.fetchSiteSecurityStatus();await page.fetchSiteSecurityStatus();assert.equal(reads,1);assert.equal(page.siteSecurityStateText('https'),'website.security_checking');assert.equal(page.siteSecurityClass('https'),'badge-info');
    wait.resolve(status([]));await first;
});

test('a read started before a policy change cannot restore stale protection claims', async () => {
    const {page,context}=setup();const old=deferred();context.api=()=>old.promise;
    const first=page.fetchSiteSecurityStatus();page.refreshSiteSecurityAfterChange();
    context.api=async()=>status([{key:'xmlrpc',state:'disabled',effective:false}]);await page.fetchSiteSecurityStatus();
    old.resolve(status([{key:'xmlrpc',state:'effective',effective:true}]));await first;
    assert.equal(page.siteSecurityStateText('xmlrpc'),'website.security_state_disabled');
});

test('website security tab loads on demand and remains available to PHP sites', async () => {
    const {page,calls}=setup();page.site.site_type='php';
    // Overview has its own lazy reads; this test measures only the security tab.
    page.loadSSLRenewal=async()=>{};page.fetchAIDevelopment=async()=>{};page.fetchPHPRuntimes=async()=>{};
    page.setDetailTab('overview');assert.equal(calls.length,0);
    page.setDetailTab('security');assert.equal(page.detailTab,'security');await new Promise(resolve=>setImmediate(resolve));assert.equal(calls.length,1);
    page.setDetailTab('overview');page.setDetailTab('security');assert.equal(calls.length,1);
    page.securityStatus={checks:[{key:'xmlrpc',state:'unsupported',effective:null,configured:null}]};assert.equal(page.siteSecurityStateText('xmlrpc'),'website.security_state_unsupported');
});

test('security policy save snapshots its two edits and preserves saved cache/debug settings and other drafts', async () => {
    const {page,context,calls}=setup();const wait=deferred();context.api=(url,options)=>{calls.push({url,options});return wait.promise;};
    page.xmlrpcEnabled=true;page.disableApplicationPasswords=false;page.lscacheEnabled=true;page.wpDebug=true;page.disableWPUpdates=true;
    const first=page.saveSiteSecurityPolicy();page.xmlrpcEnabled=false;await page.saveSiteSecurityPolicy();assert.equal(calls.length,1);
    const body=calls[0].options.body;assert.equal(body.xmlrpc_enabled,true);assert.equal(body.disable_application_passwords,false);assert.equal(body.litespeed_cache_enabled,false);assert.equal(body.wp_debug_enabled,false);assert.equal(body.disable_wp_updates,false);
    wait.resolve({success:true});await first;assert.equal(page.site.xmlrpc_enabled,true);assert.equal(page.xmlrpcEnabled,false);assert.equal(page.lscacheEnabled,true);assert.equal(page.site.litespeed_cache_enabled,false);
});

test('failed, incomplete or locked policy configuration cannot be marked saved or sent as defaults', async () => {
    const {page,context,calls,notices}=setup();page.site={id:1,site_type:'wordpress'};await page.saveSiteSecurityPolicy();assert.equal(calls.length,0);
    page.site=site();page.site.file_lock_enabled=true;await page.saveSiteSecurityPolicy();assert.equal(calls.length,0);
    page.site.file_lock_enabled=false;page.xmlrpcEnabled=true;context.api=async()=>({success:false,message:'failed'});await page.saveSiteSecurityPolicy();assert.equal(page.site.xmlrpc_enabled,false);assert.equal(page.xmlrpcEnabled,true);assert.equal(page.optimizationSaving,false);assert.equal(notices.at(-1)[1],'error');
});

test('saving cache settings never applies unsaved security tab edits', async () => {
    const {page,context,calls}=setup();context.api=async(url,options)=>{calls.push({url,options});return {success:true};};
    page.xmlrpcEnabled=true;page.disableApplicationPasswords=false;page.lscacheEnabled=true;
    await page.saveWPOptimizations();const body=calls[0].options.body;
    assert.equal(body.xmlrpc_enabled,false);assert.equal(body.disable_application_passwords,true);assert.equal(Object.hasOwn(body,'litespeed_cache_enabled'),false);assert.equal(page.xmlrpcEnabled,true);assert.equal(page.disableApplicationPasswords,false);
});

test('component readiness and isolated core evidence never become verified request protection', () => {
    const {page}=setup();
    page.securityStatus={checks:[{key:'login_protection',state:'ready',configured:true,runtime_ready:true,effective:null},{key:'application_passwords',state:'runtime_verified',configured:true,runtime_ready:true,effective:null}]};
    assert.equal(page.siteSecurityStateText('login_protection'),'site_security.state_ready');
    assert.equal(page.siteSecurityStateText('application_passwords'),'site_security.state_runtime_verified');
    assert.notEqual(page.siteSecurityClass('login_protection'),'badge-success');
    page.securityStatus.checks[0].runtime_ready=false;
    assert.equal(page.siteSecurityStateText('login_protection'),'website.security_state_unknown');
});
