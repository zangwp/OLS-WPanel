const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const { test } = require('node:test');
const source = fs.readFileSync(path.join(__dirname, '../../web/templates/account_security.html'), 'utf8').match(/<script>([\s\S]*?)<\/script>/)[1];
const defer=()=>{let resolve,reject;const promise=new Promise((a,b)=>{resolve=a;reject=b;});return {promise,resolve,reject};};
const ok=data=>({success:true,data});
const clone=value=>JSON.parse(JSON.stringify(value));
function defaultResponse(url){if(url==='/auth/mfa')return ok({enabled:false,recovery_codes_remaining:0});if(url==='/auth/sessions')return ok({sessions:[]});if(url.startsWith('/auth/audit?'))return ok({events:[],page:1,page_size:20,total:0});if(url==='/auth/security-notifications')return ok({enabled:false,smtp_configured:false,webhook_configured:false});return ok({});}
function setup(api=async url=>defaultResponse(url),extra={}){
 const listeners=new Map(),c={api,t:key=>key,confirmModal:async()=>true,document:{body:{dataset:{lang:'en-US'}}},window:{addEventListener:(event,fn)=>listeners.set(event,fn),removeEventListener:event=>listeners.delete(event)},...extra};
 vm.createContext(c);vm.runInContext(source,c);return {m:c.accountSecurity(),c,listeners};
}

test('unknown account state cannot start sensitive actions or notification writes',async()=>{
 let calls=0;const {m}=setup(async()=>{calls++;return ok({});});m.beginMFA('setup');await m.submitMFA();await m.revokeSession({id:'other'});await m.revokeOtherSessions();await m.saveNotifications();assert.equal(calls,0);assert.equal(m.mfaAction,'');
});

test('setup is not enabled until verification and recovery codes require explicit acknowledgement',async()=>{
 const calls=[];let enabled=false;const {m}=setup(async(url,opt)=>{
  calls.push({url,opt});if(url.endsWith('/setup'))return ok({secret:'SECRET',otpauth_url:'otpauth://totp/Panel?secret=SECRET',expires_at:1800000000});
  if(url.endsWith('/confirm')){enabled=true;return ok({enabled:true,recovery_codes:['ABCD-EFGH','IJKL-MNOP']});}
  if(url==='/auth/mfa')return ok({enabled,recovery_codes_remaining:2});return defaultResponse(url);
 });
 await m.fetchMFA();m.beginMFA('setup');m.mfaPassword='current password';await m.submitMFA();assert.equal(m.mfa.enabled,false);assert.equal(m.setupData.secret,'SECRET');assert.equal(m.recoveryCodes.length,0);
 m.mfaCode='123456';await m.submitMFA();assert.equal(m.mfa.enabled,true);assert.deepEqual(clone(m.recoveryCodes),['ABCD-EFGH','IJKL-MNOP']);assert.equal(m.mfaPassword,'');assert.equal(m.mfaCode,'');assert.equal(m.setupData,null);
 assert.equal(calls.find(c=>c.url.endsWith('/confirm')).opt.allowAuthFailure,true);
 m.finishRecoveryCodes();assert.equal(m.recoveryCodes.length,2);m.beginMFA('regenerate');assert.equal(m.mfaAction,'');
 m.recoverySaved=true;m.finishRecoveryCodes();assert.equal(m.recoveryCodes.length,0);
});

test('setup confirmation rejects malformed OTP locally and duplicate submission uses one request',async()=>{
 const pending=defer();let calls=0;const {m}=setup(async(url)=>{if(url.endsWith('/confirm')){calls++;return pending.promise;}return defaultResponse(url);});
 m.mfaLoaded=true;m.mfaAction='setup';m.setupData={secret:'X'};m.mfaPassword='pw';m.mfaCode='x';await m.submitMFA();assert.equal(calls,0);
 m.mfaCode='123456';const first=m.submitMFA();await m.submitMFA();assert.equal(calls,1);assert.equal(m.mfaBusy,true);pending.resolve(ok({recovery_codes:['CODE']}));await first;assert.equal(m.mfaBusy,false);
});

test('bad MFA code remains retryable and expired setup returns to key creation',async()=>{
 let code='mfa_invalid_code';const {m}=setup(async()=>{const e=Error('backend');e.code=code;throw e;});
 m.mfaLoaded=true;m.mfaAction='setup';m.setupData={secret:'X'};m.mfaPassword='pw';m.mfaCode='123456';await m.submitMFA();assert.equal(m.mfaActionError,'account_security.mfa_invalid_code');assert.equal(m.setupData.secret,'X');assert.equal(m.mfaBusy,false);
 code='mfa_setup_expired';await m.submitMFA();assert.equal(m.setupData,null);assert.equal(m.mfaAction,'setup');
});

for(const action of ['disable','regenerate'])test(action+' requires both password and code and preserves the submitted credentials',async()=>{
 let call;const pending=defer();const {m}=setup(async(url,opt)=>{if(opt?.method){call={url,opt};return pending.promise;}return defaultResponse(url);});
 m.mfaLoaded=true;m.mfa.enabled=true;m.beginMFA(action);m.mfaPassword='pw';await m.submitMFA();assert.equal(call,undefined);
 m.mfaCode='RECOVERY-CODE';const saving=m.submitMFA();m.mfaPassword='changed';m.mfaCode='changed';assert.deepEqual(clone(call.opt.body),{current_password:'pw',code:'RECOVERY-CODE'});
 pending.resolve(ok({recovery_codes:action==='regenerate'?['NEW']:undefined}));await saving;assert.equal(m.mfaPassword,'');assert.equal(m.mfaCode,'');
});

test('failed status refresh cannot destroy newly returned one-time recovery codes',async()=>{
 const {m}=setup(async(url,opt)=>{if(opt?.method)return ok({recovery_codes:['ONLY-COPY']});throw Error('offline');});
 m.mfaLoaded=true;m.mfa.enabled=true;m.beginMFA('regenerate');m.mfaPassword='pw';m.mfaCode='123456';await m.submitMFA();assert.equal(m.recoveryCodes[0],'ONLY-COPY');assert.equal(m.mfaLoaded,false);assert.equal(m.mfaError,'offline');
});

test('leaving with unsaved codes asks for confirmation; disposal removes the listener and secrets',async()=>{
 const {m,listeners}=setup();await m.init();m.recoveryCodes=['SECRET'];let prevented=0;const event={preventDefault(){prevented++;}};
 listeners.get('beforeunload')(event);assert.equal(prevented,1);m.recoverySaved=true;listeners.get('beforeunload')(event);assert.equal(prevented,1);
 m.mfaPassword='pw';m.destroy();assert.equal(listeners.size,0);assert.equal(m.mfaPassword,'');assert.equal(m.recoveryCodes.length,0);
});

test('copy failure retains codes and directs the user to download or select them',async()=>{
 const {m}=setup(undefined,{navigator:{clipboard:{writeText:async()=>{throw Error('denied');}}}});m.recoveryCodes=['SAVE-ME'];await m.copyRecoveryCodes();assert.equal(m.recoveryCodes[0],'SAVE-ME');assert.equal(m.recoverySaved,false);assert.equal(m.mfaActionError,'account_security.copy_failed');
});

test('MFA Unix expiry seconds are formatted as the actual year',()=>{const {m}=setup();assert.match(m.formatDate(1800000000),/2027/);});

test('a stale sessions response cannot resurrect a revoked session',async()=>{
 const old=defer();let calls=0;const {m}=setup(()=>++calls===1?old.promise:Promise.resolve(ok({sessions:[{id:'current',current:true}]})));
 const first=m.fetchSessions();await m.fetchSessions();old.resolve(ok({sessions:[{id:'revoked'}]}));await first;assert.equal(m.sessions[0].id,'current');assert.equal(m.sessionsLoading,false);
});

test('current session is protected and revoke-others confirmation prevents duplicate writes',async()=>{
 const confirmation=defer();const calls=[];const {m}=setup(async(url,opt)=>{calls.push({url,opt});return defaultResponse(url);},{confirmModal:()=>confirmation.promise});
 m.sessionsLoaded=true;m.sessions=[{id:'self',current:true},{id:'other',current:false}];await m.revokeSession(m.sessions[0]);assert.equal(calls.length,0);
 const first=m.revokeOtherSessions();await m.revokeOtherSessions();assert.equal(calls.length,0);confirmation.resolve(true);await first;assert.equal(calls.filter(c=>c.opt?.method==='POST').length,1);assert.equal(m.sessionBusy,false);
});

test('failed revoke keeps inline error and never displays a success notice',async()=>{
 const {m}=setup(async()=>{throw Error('cannot revoke');});m.sessionsLoaded=true;m.sessions=[{id:'other'}];await m.revokeSession(m.sessions[0]);assert.equal(m.sessionsError,'cannot revoke');assert.equal(m.sessionNotice,'');assert.equal(m.sessionBusy,false);
});

test('audit page and records commit together and stale errors do not replace the latest page',async()=>{
 const old=defer();let calls=0;const {m}=setup(()=>++calls===1?old.promise:Promise.resolve(ok({events:[{id:40}],total:41,page:3,page_size:20})));
 const first=m.fetchAudit(2);assert.equal(m.auditPage,1);await m.fetchAudit(3);old.reject(Error('stale'));await first;assert.equal(m.auditPage,3);assert.equal(m.auditEvents[0].id,40);assert.equal(m.auditPages(),3);assert.equal(m.auditError,'');assert.equal(m.auditLoading,false);
});

test('audit failure retains retry target without falsely declaring an empty result',async()=>{
 const {m}=setup(async()=>{throw Error('offline');});await m.fetchAudit(2);assert.equal(m.auditLoaded,false);assert.equal(m.auditRequestedPage,2);assert.equal(m.auditError,'offline');
});

test('notification settings require load, retain channel state, and serialize saves',async()=>{
 const save=defer();let puts=0;const {m}=setup(async(url,opt)=>{if(opt?.method){puts++;return save.promise;}return ok({enabled:false,smtp_configured:false,webhook_configured:true});});
 await m.saveNotifications();assert.equal(puts,0);await m.fetchNotifications();assert.equal(m.notifications.webhook_configured,true);m.notificationDraft=true;const first=m.saveNotifications();await m.saveNotifications();assert.equal(puts,1);save.resolve(ok({}));await first;assert.equal(m.notifications.enabled,true);assert.equal(m.notificationsSaving,false);
});

test('notification failure preserves the last confirmed setting and permits retry',async()=>{
 const {m}=setup(async()=>{throw Error('offline');});m.notificationsLoaded=true;m.notificationDraft=true;await m.saveNotifications();assert.equal(m.notifications.enabled,false);assert.equal(m.notificationDraft,true);assert.equal(m.notificationsError,'offline');assert.equal(m.notificationsSaving,false);
});


test('audit and notification enums resolve full translations with safe unknown fallbacks',()=>{
 const {m}=setup();
 for(const event of ['login_success','login_failure','login_blocked','credentials_changed','mfa_enabled','mfa_disabled','recovery_used','recovery_regenerated','session_revoked','sessions_revoked','notifications_changed','logout']) assert.equal(m.eventLabel(event),'account_security.event_'+event);
 for(const status of ['none','pending','sent','failed','suppressed','disabled','unconfigured']) assert.equal(m.notificationLabel(status),'account_security.notification_'+status);
 for(const value of ['future_event','toString','constructor','__proto__']) {assert.equal(m.eventLabel(value),value);assert.equal(m.notificationLabel(value),value);}
 assert.equal(m.eventLabel(null),'—');assert.equal(m.notificationLabel(''),'—');
});

test('all MFA response error codes resolve their full translation and preserve safe fallback messages',async()=>{
 let code;const {m}=setup(async()=>{const error=Error('Request could not be completed');error.code=code;throw error;});
 for(code of ['mfa_invalid_code','mfa_invalid_password','mfa_rate_limited','mfa_already_enabled','mfa_not_enabled','mfa_setup_expired','mfa_unavailable','future_error','toString']) {
  m.mfaLoaded=true;m.mfaAction='setup';m.mfaPassword='synthetic';m.setupData=null;await m.submitMFA();
  assert.equal(m.mfaActionError,code.startsWith('mfa_')?'account_security.'+code:'Request could not be completed');assert.equal(m.mfaBusy,false);
 }
});
