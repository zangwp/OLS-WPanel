const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const { test } = require('node:test');
const source = fs.readFileSync(path.join(__dirname, '../../web/templates/security.html'), 'utf8').match(/<script>([\s\S]*?)<\/script>/)[1];
const defer = () => { let resolve, reject; const promise = new Promise((a,b) => { resolve=a; reject=b; }); return { promise, resolve, reject }; };
const required = { fail2ban_maxretry: '5', fail2ban_findtime: '60', auto_whitelist_enabled: 'true', wp_sqli_block_enabled: 'true', wp_sqli_autoban_enabled: 'true', wp_sqli_ban_threshold: '5', wp_sqli_ban_window_seconds: '600', whitelist_ips: '', ssh_whitelist_ips: '', wp_security_log_whitelist: '', telemetry_enabled: 'false', telemetry_url: '' };
const rows = values => Object.entries({ ...required, ...values }).map(([skey,svalue]) => ({ skey,svalue }));
function setup(api, extra={}) { const c = { api, t: key => key, showToast() {}, confirmModal: async()=>true, location:{hash:'#account'}, ...extra }; vm.createContext(c); vm.runInContext(source,c); return { m: c.securitySettings(), c }; }
const ok = data => ({ success:true, data });

test('all settings writes and whitelist refresh stay blocked before loading', async()=>{
 let calls=0; const {m}=setup(async()=>{calls++;return ok({});});
 for(const method of ['saveFail2ban','saveSQLi','saveTelemetry','saveWebWhitelist','saveSSHWhitelist','saveGooglebotRanges','saveWPSecurityLogWhitelist','refreshWhitelist']) await m[method]();
 assert.equal(calls,0); assert.equal(m.settingsDisabled(),true);
});

for(const data of [null, {}, [], [{skey:'fail2ban_maxretry',svalue:'5'}], rows().map((s,i)=>i? s : {skey:s.skey,svalue:null})]) {
 test('incomplete settings cannot unlock writes: '+JSON.stringify(data).slice(0,65),async()=>{
  let writes=0; const {m}=setup(async(url,options)=>{if(options?.method)writes++; return ok(data);});
  await m.fetchSettings(); await m.saveSQLi(); assert.equal(m.settingsLoaded,false); assert.ok(m.settingsError); assert.equal(writes,0);
 });
}

test('failed load is inline and a successful explicit retry unlocks configuration',async()=>{
 let fail=true; const {m}=setup(async()=>{if(fail)throw Error('offline');return ok(rows());});
 await m.fetchSettings(); assert.match(m.settingsError,/offline/); assert.equal(m.settingsDisabled(),true);
 fail=false; await m.fetchSettings(); assert.equal(m.settingsLoaded,true); assert.equal(m.settings.auto_whitelist_enabled,true); assert.equal(m.settingsError,'');
});

test('different save buttons share one lock and submit a snapshot',async()=>{
 const saving=defer(), calls=[]; const {m}=setup(async(url,opt)=>{calls.push({url,opt}); if(opt?.method==='PUT')return saving.promise;return ok({fail2ban:{active:true}});});
 m.settingsLoaded=true; m.settings={...required,fail2ban_maxretry:7,auto_whitelist_enabled:true};
 const pending=m.saveFail2ban(); m.settings.fail2ban_maxretry=9; await m.saveWebWhitelist(); await m.refreshWhitelist();
 assert.equal(calls.length,1); assert.equal(calls[0].opt.body.fail2ban_maxretry,'7'); assert.equal(m.settingsSaving,true);
 saving.resolve(ok({})); await pending; assert.equal(m.settingsSaving,false); assert.equal(m.settings.fail2ban_maxretry,9); assert.equal(m.mutationNotice,'security_center.saved_runtime_refreshed');
});

test('failed save never reports success, releases lock, and permits a retry',async()=>{
 let fail=true; const {m}=setup(async()=>{if(fail)throw Error('apply failed');return ok({});});m.settingsLoaded=true;
 await m.saveWebWhitelist(); assert.equal(m.mutationNotice,''); assert.equal(m.mutationError,'apply failed'); assert.equal(m.settingsSaving,false);
 fail=false; await m.saveWebWhitelist(); assert.equal(m.mutationError,''); assert.ok(m.mutationNotice);
});

test('successful save with failed runtime read is not described as active protection',async()=>{
 const {m}=setup(async(url,opt)=>{if(opt?.method)return ok({});throw Error('status offline');});m.settingsLoaded=true;
 await m.saveSSHWhitelist(); assert.equal(m.mutationNotice,'security_center.saved_status_unavailable'); assert.equal(m.statusError,'status offline');
});

test('stale runtime error cannot replace a newer successful status',async()=>{
 const first=defer();let calls=0;const {m}=setup(()=>++calls===1?first.promise:Promise.resolve(ok({active_bans:3})));
 const old=m.fetchStatus();await m.fetchStatus(); first.reject(Error('old error'));await old;
 assert.equal(m.securityStatus.active_bans,3);assert.equal(m.statusError,'');assert.equal(m.statusLoading,false);
});

test('telemetry confirmation owns the lock while open',async()=>{
 const confirmation=defer();let writes=0;const {m}=setup(async()=>{writes++;return ok({});},{confirmModal:()=>confirmation.promise});
 m.settingsLoaded=true;m.telemetryOriginalEnabled=true;m.settings={telemetry_enabled:false};
 const first=m.saveTelemetry();await m.saveFail2ban();assert.equal(writes,0);assert.equal(m.settingsSaving,true);
 confirmation.resolve(false);await first;assert.equal(writes,0);assert.equal(m.settingsSaving,false);assert.equal(m.telemetrySaving,false);
});

test('CDN loading has its own guard independent of security settings',async()=>{
 let writes=0,fail=true;const {m}=setup(async(url,opt)=>{if(opt?.method){writes++;return ok({});}if(fail)throw Error('CDN offline');return ok([]);});
 m.settingsLoaded=true;await m.fetchCDNGroups();await m.saveCDNGroup();await m.deleteCDNGroup({id:4});assert.equal(writes,0);assert.equal(m.cdnLoaded,false);assert.match(m.cdnError,/CDN offline/);
 fail=false;await m.fetchCDNGroups();assert.equal(m.cdnLoaded,true);assert.equal(m.settingsLoaded,true);
});

test('CDN deletion snapshots target and locks before confirmation',async()=>{
 const confirmation=defer(),calls=[];const {m}=setup(async(url,opt)=>{calls.push({url,opt});return ok(url.includes('groups') && !opt?.method?[]:{});},{confirmModal:()=>confirmation.promise});
 m.cdnLoaded=true;const group={id:5,name:'Edge'};const pending=m.deleteCDNGroup(group);group.id=9;await m.deleteCDNGroup({id:7,name:'Other'});
 confirmation.resolve(true);await pending;assert.equal(calls.filter(c=>c.opt?.method==='DELETE').length,1);assert.equal(calls[0].url,'/security/cdn-realip-groups/5');assert.equal(m.cdnGroupSaving,false);
});

test('queued whitelist refresh is never reported as a completed list update',async()=>{
 const {m}=setup(async()=>ok({}));m.settingsLoaded=true;await m.refreshWhitelist();assert.equal(m.mutationNotice,'security_center.refresh_queued');
});
