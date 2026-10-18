const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const { test } = require('node:test');
const source = fs.readFileSync(path.join(__dirname, '../../web/templates/security.html'), 'utf8').match(/<script>([\s\S]*?)<\/script>/)[1];
const defer = () => { let resolve, reject; const promise = new Promise((a,b) => { resolve=a; reject=b; }); return { promise, resolve, reject }; };
const required = { fail2ban_maxretry: '5', fail2ban_findtime: '60', auto_whitelist_enabled: 'true', wp_sqli_block_enabled: 'true', wp_sqli_autoban_enabled: 'true', wp_sqli_ban_threshold: '5', wp_sqli_ban_window_seconds: '600', whitelist_ips: '', ssh_whitelist_ips: '', wp_security_log_whitelist: '', telemetry_enabled: 'false', telemetry_url: '' };
const rows = values => Object.entries({ ...required, ...values }).map(([skey,svalue]) => ({ skey,svalue }));
function setup(api, extra={}) {
 const timers=new Map();let timerID=0;
 const c = { api, t: key => key, showToast() {}, confirmModal: async()=>true, location:{hash:'#account'}, AbortController,
  setTimeout(fn,ms){const id=++timerID;timers.set(id,{fn,ms});return id;},clearTimeout(id){timers.delete(id);},...extra };
 vm.createContext(c);vm.runInContext(source,c);
 return {m:c.securitySettings(),c,timers,async runTimer(){const [id,timer]=timers.entries().next().value;timers.delete(id);await timer.fn();}};
}
const ok = data => ({ success:true, data });

test('IP update admission and completion reads never lock unrelated save controls or submit settings', async()=>{
 const admission=defer(), reload=defer(), calls=[];
 const {m}=setup(async(url,opt)=>{
  calls.push({url,opt});
  if(opt?.method==='POST')return admission.promise;
  if(url==='/security/settings')return reload.promise;
  if(url==='/security/status')return ok({cloudflare_trust:'configured'});
  return ok({task_id:'refresh-1',kind:'refresh_whitelist',status:'success',result_code:'refresh_completed'});
 });
 m.settingsLoaded=true;m.settings=m.parseSettings(rows());
 const pending=m.refreshWhitelist();
 assert.equal(m.settingsDisabled(),false);assert.equal(m.whitelistRefreshing,true);
 await m.refreshWhitelist();await m.reloadWhitelistData();assert.equal(calls.length,1);
 admission.resolve(ok({task_id:'refresh-1',kind:'refresh_whitelist',status:'waiting'}));
 await new Promise(resolve=>setImmediate(resolve));
 assert.equal(m.whitelistDataLoading,true);assert.equal(m.whitelistRefreshing,true);assert.equal(m.settingsDisabled(),false);
 m.settings.whitelist_ips='203.0.113.20';m.settings.ssh_whitelist_ips='203.0.113.21';m.whitelistScheduleEnabled=false;
 reload.resolve(ok(rows({cloudflare_realip_ips:'173.245.48.0/20'})));await pending;
 assert.equal(m.whitelistDataLoading,false);assert.equal(m.whitelistRefreshing,false);assert.equal(m.settingsDisabled(),false);
 assert.equal(m.settings.whitelist_ips,'203.0.113.20');assert.equal(m.settings.ssh_whitelist_ips,'203.0.113.21');assert.equal(m.whitelistScheduleEnabled,false);
 assert.deepEqual(calls.filter(c=>c.opt?.method).map(c=>[c.url,c.opt.method]),[['/security/whitelist/refresh','POST']]);
});

for(const editing of ['before','during','none'])test('IP data reload preserves Googlebot drafts: '+editing,async()=>{
 const response=defer();const {m}=setup(async url=>url==='/security/settings'?response.promise:ok({}));
 m.settingsLoaded=true;m.settings=m.parseSettings(rows({googlebot_ips:'66.249.64.0/19'}));m.googlebotRangesOriginal=m.settings.googlebot_ips;
 if(editing==='before')m.settings.googlebot_ips='192.0.2.0/24';
 const pending=m.reloadWhitelistData();
 if(editing==='during')m.settings.googlebot_ips='192.0.2.0/24';
 assert.equal(m.settingsDisabled(),false);await m.reloadWhitelistData();
 response.resolve(ok(rows({googlebot_ips:'198.51.100.0/24',googlebot_ips_source:'official'})));await pending;
 assert.equal(m.settings.googlebot_ips,editing==='none'?'198.51.100.0/24':'192.0.2.0/24');
 assert.equal(m.googlebotRangesOriginal,'198.51.100.0/24');assert.equal(m.whitelistDataLoading,false);
});

test('an older IP read cannot overwrite a newer manual Googlebot import',async()=>{
 const old=defer();let reads=0;const {m}=setup(async(url,opt)=>{
  if(url==='/security/settings')return ++reads===1?old.promise:ok(rows({googlebot_ips:'192.0.2.0/24',googlebot_ips_source:'manual'}));
  return ok({});
 });
 m.settingsLoaded=true;m.settings=m.parseSettings(rows());const pending=m.reloadWhitelistData();
 m.settings.googlebot_ips='192.0.2.0/24';await m.saveGooglebotRanges();
 old.resolve(ok(rows({googlebot_ips:'198.51.100.0/24',googlebot_ips_source:'official'})));await pending;
 assert.equal(m.settings.googlebot_ips,'192.0.2.0/24');assert.equal(m.settings.googlebot_ips_source,'manual');assert.equal(m.googlebotRangesOriginal,'192.0.2.0/24');
});

test('failed IP data reload resets only its own loading state and keeps drafts',async()=>{
 const {m}=setup(async()=>{throw Error('offline');});m.settingsLoaded=true;m.settings.googlebot_ips='192.0.2.0/24';
 await m.reloadWhitelistData();assert.equal(m.whitelistDataLoading,false);assert.equal(m.settingsDisabled(),false);assert.equal(m.settings.googlebot_ips,'192.0.2.0/24');assert.equal(m.whitelistError,'offline');
});

test('retry after a successful Googlebot import and failed read preserves unrelated security drafts',async()=>{
 let reads=0;const calls=[];const {m}=setup(async(url,opt)=>{
  calls.push({url,method:opt?.method||'GET'});
  if(url==='/security/settings'){if(++reads===2)throw Error('reload offline');return ok(rows({googlebot_ips:reads===1?'old-google':'saved-google',googlebot_ips_source:'manual',cloudflare_realip_ips:reads===1?'old-cf':'fresh-cf'}));}
  return ok({});
 });
 await m.fetchSettings();m.settings.whitelist_ips='unsaved-web';m.settings.ssh_whitelist_ips='unsaved-ssh';m.settings.wp_security_log_whitelist='/unsaved-path';m.settings.telemetry_url='https://example.com/unsaved';m.settings.fail2ban_maxretry='8';m.whitelistScheduleEnabled=false;m.settings.googlebot_ips='submitted-google';
 await m.saveGooglebotRanges();assert.equal(m.settingsLoaded,false);assert.equal(m.settingsDisabled(),true);await m.fetchSettings();
 assert.equal(m.settings.whitelist_ips,'unsaved-web');assert.equal(m.settings.ssh_whitelist_ips,'unsaved-ssh');assert.equal(m.settings.wp_security_log_whitelist,'/unsaved-path');assert.equal(m.settings.telemetry_url,'https://example.com/unsaved');assert.equal(m.settings.fail2ban_maxretry,'8');assert.equal(m.whitelistScheduleEnabled,false);
 assert.equal(m.settings.googlebot_ips,'saved-google');assert.equal(m.googlebotRangesOriginal,'saved-google');assert.equal(m.settings.cloudflare_realip_ips,'fresh-cf');assert.equal(m.settingsLoaded,true);assert.equal(m.settingsError,'');
 assert.deepEqual(calls.filter(call=>call.method!=='GET'),[{url:'/security/whitelist/googlebot',method:'PUT'}]);
});

test('full security refresh preserves edits made during the read and can update clean saved fields',async()=>{
 const refresh=defer();let current=rows({whitelist_ips:'old'}),reads=0;const {m}=setup(async(url,opt)=>url==='/security/settings'&&!opt?.method?(++reads===2?refresh.promise:ok(current)):ok({}));
 await m.fetchSettings();const loading=m.fetchSettings();m.settings.whitelist_ips='during-read';m.settings.googlebot_ips='new-google-draft';m.whitelistScheduleEnabled=false;
 refresh.resolve(ok(rows({whitelist_ips:'external',googlebot_ips:'official',fail2ban_maxretry:'9'})));await loading;
 assert.equal(m.settings.whitelist_ips,'during-read');assert.equal(m.settings.googlebot_ips,'new-google-draft');assert.equal(m.whitelistScheduleEnabled,false);assert.equal(m.settings.fail2ban_maxretry,9);
 await m.saveWebWhitelist();current=rows({whitelist_ips:'later-external',googlebot_ips:'official',fail2ban_maxretry:'9'});await m.fetchSettings();assert.equal(m.settings.whitelist_ips,'later-external');assert.equal(m.settings.googlebot_ips,'new-google-draft');
});

test('destroy prevents an in-flight full settings read from replacing drafts or unlocking controls',async()=>{
 const response=defer();const {m}=setup(()=>response.promise);const pending=m.fetchSettings();m.settings.whitelist_ips='draft';m.destroy();response.resolve(ok(rows()));await pending;
 assert.equal(m.settings.whitelist_ips,'draft');assert.equal(m.settingsLoaded,false);assert.equal(m.settingsLoading,false);
});

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
 const {m,timers}=setup(async()=>ok({task_id:'refresh-1',kind:'refresh_whitelist',status:'waiting'}));m.settingsLoaded=true;
 await m.refreshWhitelist();assert.equal(m.whitelistNotice,'security_center.refresh_queued');assert.equal(m.mutationNotice,'');
 assert.equal(m.whitelistRefreshing,true);assert.equal(timers.size,1);assert.equal(m.settingsSaving,false);
});

test('editing another CDN opens its form while built-in Cloudflare remains automatic',async()=>{
 const {m}=setup(async()=>ok([]));m.cdnLoaded=true;
 m.cdnGroups=[{id:1,provider:'cloudflare',builtin:true},{id:4,name:'Other CDN',provider:'custom',header_name:'X-Forwarded-For',ip_ranges:'192.0.2.0/24',enabled:true}];
 assert.equal(m.cdnFormExpanded,false);assert.equal(m.cdnOtherGroups().length,1);
 m.editCDNGroup(m.cdnGroups[0]);assert.equal(m.cdnFormExpanded,false);assert.equal(m.cdnGroupForm.id,null);
 m.editCDNGroup(m.cdnGroups[1]);assert.equal(m.cdnFormExpanded,true);assert.equal(m.cdnGroupForm.id,4);assert.equal(m.cdnGroupForm.ip_ranges,'192.0.2.0/24');
 m.resetCDNGroupForm();assert.equal(m.cdnFormExpanded,false);assert.equal(m.cdnGroupForm.id,null);
});

test('failed CDN save keeps the expanded draft and successful retry closes it',async()=>{
 let fail=true;const {m}=setup(async(url,opt)=>{if(opt?.method){if(fail)throw Error('trusted proxy update failed');return ok({});}return ok(url.includes('groups')?[]:{});});
 m.cdnLoaded=true;m.editCDNGroup({id:4,name:'Other CDN',provider:'custom',header_name:'X-Forwarded-For',ip_ranges:'192.0.2.0/24',enabled:true});
 await m.saveCDNGroup();assert.equal(m.cdnFormExpanded,true);assert.equal(m.cdnGroupForm.id,4);assert.equal(m.cdnError,'trusted proxy update failed');
 fail=false;await m.saveCDNGroup();assert.equal(m.cdnFormExpanded,false);assert.equal(m.cdnGroupForm.id,null);assert.equal(m.cdnError,'');
});

test('Cloudflare status never promotes cache presence or zero bindings to verified configuration',()=>{
 const {m}=setup(async()=>ok({}));
 m.settings={cloudflare_realip_ips:'192.0.2.0/24\n\n2001:db8::/32'};assert.equal(m.cdnBuiltinStatus(),'security.status_unknown');
 m.settingsLoaded=true;m.securityStatus={cdn_invalid_bindings:0};assert.equal(m.cdnBuiltinStatus(),'security.status_unknown');assert.equal(m.cdnTrustClass(),'text-gray-500');
 for(const state of ['missing','pending','disabled','configured']) {
  m.securityStatus.cloudflare_trust=state;assert.equal(m.cdnBuiltinStatus(),'security.cdn_trust_'+state);
  assert.equal(m.cdnTrustClass()==='text-green-400',state==='configured');
 }
 m.securityStatus.cdn_invalid_bindings=1;assert.equal(m.cdnTrustLabel(),'security.status_attention');assert.equal(m.cdnTrustClass(),'text-yellow-400');
 m.settingsError='cache unreadable';assert.equal(m.cdnBuiltinStatus(),'security.status_unknown');
});

test('refresh completion reloads cache data and status while preserving unsaved configuration',async()=>{
 let status='waiting';const calls=[];
 const {m,timers,runTimer}=setup(async(url,opt)=>{
  calls.push({url,opt});
  if(url==='/security/settings')return ok(rows({cloudflare_realip_ips:'173.245.48.0/20',whitelist_ips:'server copy'}));
  if(url==='/security/status')return ok({cloudflare_trust:'configured'});
  return ok({task_id:'refresh-1',kind:'refresh_whitelist',status,result_code:status==='success'?'refresh_completed':''});
 });
 m.settingsLoaded=true;m.settings={...required,whitelist_ips:'unsaved draft',googlebot_ips:'old'};m.whitelistScheduleEnabled=false;
 await m.refreshWhitelist();await m.refreshWhitelist();assert.equal(calls.filter(c=>c.opt?.method==='POST').length,1);
 status='running';await runTimer();assert.equal(m.whitelistNotice,'security.refresh_running');assert.equal(m.whitelistRefreshing,true);
 status='success';await runTimer();assert.equal(m.whitelistNotice,'security.refresh_completed');assert.equal(m.whitelistRefreshing,false);assert.equal(timers.size,0);
 assert.equal(m.settings.cloudflare_realip_ips,'173.245.48.0/20');assert.equal(m.settings.whitelist_ips,'unsaved draft');assert.equal(m.whitelistScheduleEnabled,false);assert.equal(m.securityStatus.cloudflare_trust,'configured');
});

test('failed refresh is terminal, refreshes current data, and never reports success',async()=>{
 const {m,timers}=setup(async(url,opt)=>{
  if(url==='/security/settings')return ok(rows());if(url==='/security/status')return ok({cloudflare_trust:'missing'});
  return ok({task_id:'refresh-1',kind:'refresh_whitelist',status:opt?.method?'waiting':'failed',result_code:opt?.method?'':'refresh_failed'});
 });
 m.settingsLoaded=true;await m.refreshWhitelist();assert.equal(m.whitelistNotice,'');assert.equal(m.whitelistError,'security.refresh_failed');assert.equal(m.whitelistTaskID,'');assert.equal(timers.size,0);
});

test('successful task with unreadable status remains distinguishable from verified configuration',async()=>{
 const {m}=setup(async(url,opt)=>{
  if(url==='/security/settings')return ok(rows());if(url==='/security/status')throw Error('offline');
  return ok({task_id:'refresh-1',kind:'refresh_whitelist',status:opt?.method?'waiting':'success',result_code:'refresh_completed'});
 });
 m.settingsLoaded=true;await m.refreshWhitelist();assert.equal(m.whitelistNotice,'security.refresh_completed_status_unavailable');assert.equal(m.cdnTrustClass(),'text-gray-500');
});

test('polling errors stop after three failures and retry checks the same task without another write',async()=>{
 let unavailable=true,posts=0;
 const {m,timers,runTimer}=setup(async(url,opt)=>{
  if(opt?.method){posts++;return ok({task_id:'refresh-1',kind:'refresh_whitelist',status:'waiting'});}
  if(unavailable)throw Error('offline');return ok({task_id:'refresh-1',kind:'refresh_whitelist',status:'running'});
 });
 m.settingsLoaded=true;await m.refreshWhitelist();await runTimer();await runTimer();
 assert.equal(m.whitelistRefreshing,false);assert.equal(m.whitelistTaskID,'refresh-1');assert.equal(timers.size,0);assert.equal(m.whitelistError,'security.refresh_status_unavailable');
 unavailable=false;await m.refreshWhitelist();assert.equal(posts,1);assert.equal(m.whitelistRefreshing,true);assert.equal(m.whitelistNotice,'security.refresh_running');m.destroy();
});

test('polling has a five-minute bound and expired records do not trap the update button',async()=>{
 let expired=false;
 const {m,timers,runTimer}=setup(async()=>{if(expired)throw Object.assign(Error('gone'),{status:404});return ok({task_id:'refresh-1',kind:'refresh_whitelist',status:'waiting'});});
 m.settingsLoaded=true;await m.refreshWhitelist();m.whitelistPollDeadline=Date.now()-1;await runTimer();assert.equal(timers.size,0);assert.equal(m.whitelistRefreshing,false);assert.equal(m.whitelistTaskID,'refresh-1');
 expired=true;await m.refreshWhitelist();assert.equal(m.whitelistTaskID,'');assert.equal(m.whitelistRefreshing,false);assert.equal(timers.size,0);assert.equal(m.whitelistError,'security.refresh_status_unavailable');
});

test('destroy cancels refresh polling and ignores an in-flight result',async()=>{
 const pending=defer(),started=defer();let signal;
 const {m,timers}=setup(async(url,opt)=>{if(opt?.method)return ok({task_id:'refresh-1',kind:'refresh_whitelist',status:'waiting'});signal=opt.signal;started.resolve();return pending.promise;});
 m.settingsLoaded=true;const work=m.refreshWhitelist();await started.promise;m.destroy();
 assert.equal(signal.aborted,true);pending.resolve(ok({task_id:'refresh-1',kind:'refresh_whitelist',status:'success',result_code:'refresh_completed'}));await work;
 assert.equal(timers.size,0);assert.equal(m.whitelistRefreshing,false);assert.notEqual(m.whitelistNotice,'security.refresh_completed');
});

test('destroy clears an idle poll timer',async()=>{
 const {m,timers}=setup(async()=>ok({task_id:'refresh-1',kind:'refresh_whitelist',status:'waiting'}));m.settingsLoaded=true;await m.refreshWhitelist();assert.equal(timers.size,1);m.destroy();assert.equal(timers.size,0);
});

test('foreign or inconsistent task results cannot produce a completed message',async()=>{
 const {m,timers,runTimer}=setup(async(url,opt)=>ok({task_id:'refresh-1',kind:'refresh_whitelist',status:opt?.method?'waiting':'success',result_code:'refresh_failed'}));
 m.settingsLoaded=true;await m.refreshWhitelist();await runTimer();await runTimer();assert.equal(m.whitelistRefreshing,false);assert.equal(timers.size,0);assert.equal(m.whitelistError,'security.refresh_status_unavailable');assert.notEqual(m.whitelistNotice,'security.refresh_completed');
});
