const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const { test } = require('node:test');
const source = fs.readFileSync(path.join(__dirname, '../../web/templates/alert.html'), 'utf8').match(/<script>([\s\S]*?)<\/script>/)[1];
const ok = data => ({success:true,data});
const defer = () => { let resolve,reject;const promise=new Promise((a,b)=>{resolve=a;reject=b;});return {promise,resolve,reject}; };
const data = () => ({smtp_host:'smtp.example.com',smtp_port:'587',smtp_encryption:'starttls',smtp_user:'admin@example.com',smtp_pass:'fixture',admin_email:'admin@example.com',webhook_channel:'wecom',webhook_url:'https://example.com/hook',alert_cpu:'true',alert_memory:'true',alert_oom:'true',alert_disk:'true',alert_service:'true',alert_ssl:'true',alert_backup:'true',alert_remote_backup:'false',alert_cron_fail:'true',alert_website_expiry:'true',alert_system_update:'true',alert_panel_update:'true',alert_wp_fake_search_bot:'false',alert_wp_security_threshold:'10',alert_wp_security_window_hours:'24'});
function setup(api) {const toasts=[],events=[];const c={api,t:k=>k,showToast:(...a)=>toasts.push(a),window:{dispatchEvent:e=>events.push(e)},CustomEvent:function(type,o){this.type=type;this.detail=o.detail;}};vm.createContext(c);vm.runInContext(source,c);return {c,toasts,events};}

for(const factory of ['smtpConfig','webhookConfig','alertManager'])test(factory+' blocks writes after failed or incomplete loading and permits a fresh retry',async()=>{
 let fail=true,malformed=false,writes=0;const {c}=setup(async(url,opt)=>{if(opt?.method){writes++;return ok({});}if(url==='/alert/log')return ok([]);if(fail)throw Error('offline');return ok(malformed?{}:data());});const m=c[factory]();const load=()=>factory==='alertManager'?m.fetchAll():m.fetch();
 await load();assert.equal(m.loaded,false);assert.equal(m.loadError,'offline');await m.save();if(factory==='alertManager')await m.saveWPSecCfg();else await m.test();assert.equal(writes,0);
 fail=false;malformed=true;await load();assert.equal(m.loaded,false);assert.equal(m.loadError,'followup.invalid_config');await m.save();assert.equal(writes,0);
 malformed=false;await load();assert.equal(m.loaded,true);assert.equal(m.loadError,'');await m.save();assert.equal(writes,1);
});

test('initial channel and rule loading share one read without caching later refreshes',async()=>{
 const pending=defer();let reads=0;const {c}=setup(async url=>{if(url==='/alert/log')return ok([]);reads++;return reads===1?pending.promise:ok(data());});const a=c.smtpConfig(),b=c.webhookConfig(),m=c.alertManager();const loaders=[a.fetch(),b.fetch(),m.fetchAll()];assert.equal(reads,1);pending.resolve(ok(data()));await Promise.all(loaders);await a.fetch();assert.equal(reads,2);
});

test('first-time webhook configuration is allowed without optional unseeded webhook keys',async()=>{
 const d=data();delete d.webhook_channel;delete d.webhook_url;const {c}=setup(async()=>ok(d));const m=c.webhookConfig();await m.fetch();assert.equal(m.loaded,true);assert.equal(m.cfg.webhook_channel,'wecom');assert.equal(m.cfg.webhook_url,'');
});

test('SMTP saves one immutable snapshot, prevents duplicate writes and does not mark newer edits saved',async()=>{
 const pending=defer(),writes=[];const {c,events}=setup(async(url,opt)=>{if(opt?.method){writes.push(opt.body);return pending.promise;}return ok(data());});const m=c.smtpConfig();await m.fetch();m.cfg.smtp_host='submitted.example.com';const save=m.save();m.cfg.smtp_host='new-draft.example.com';await m.save();await m.test();await m.copyConfig();assert.equal(writes.length,1);assert.equal(writes[0].smtp_host,'submitted.example.com');pending.resolve(ok({}));await save;assert.equal(m.saving,false);assert.equal(m.dirty(),true);assert.equal(events[0].detail.smtp_host,'submitted.example.com');
});

test('SMTP test and export stay blocked for unsaved edits',async()=>{
 let writes=0;const {c}=setup(async(url,opt)=>{if(opt?.method)writes++;return ok(data());});const m=c.smtpConfig();await m.fetch();m.cfg.smtp_host='new.example.com';await m.test();await m.copyConfig();assert.equal(writes,0);
});

test('failed channel save retains the draft and never reports success',async()=>{
 let fail=true;const {c,toasts}=setup(async(url,opt)=>opt?.method? (fail?{success:false,message:'write failed'}:ok({})):ok(data()));const m=c.smtpConfig();await m.fetch();m.cfg.smtp_host='new.example.com';await m.save();assert.equal(m.operationError,'write failed');assert.equal(m.dirty(),true);assert.equal(toasts.some(t=>t[1]==='success'),false);fail=false;await m.save();assert.equal(m.operationError,'');assert.equal(m.dirty(),false);
});

test('rapid alert toggles serialize requests and converge on the latest complete draft',async()=>{
 const first=defer(),last=defer(),writes=[];const {c}=setup(async(url,opt)=>{writes.push(structuredClone(opt.body));return writes.length===1?first.promise:last.promise;});const m=c.alertManager();m.loaded=true;m.rules={alert_cpu:false,alert_memory:true};const saving=m.save();m.rules.alert_cpu=true;await m.save();m.rules.alert_memory=false;await m.save();assert.equal(writes.length,1);assert.equal(writes[0].alert_cpu,'false');first.resolve(ok({}));await new Promise(r=>setImmediate(r));assert.equal(writes.length,2);assert.deepEqual(writes[1],{alert_cpu:'true',alert_memory:'false'});last.resolve(ok({}));await saving;assert.equal(m.rulesSaving,false);assert.equal(m.rulesError,'');
});

test('failed queued rule save preserves new selections for explicit retry',async()=>{
 const first=defer();let calls=0;const {c}=setup(async()=>++calls===1?first.promise:ok({}));const m=c.alertManager();m.loaded=true;m.rules={alert_cpu:false};const saving=m.save();m.rules.alert_cpu=true;await m.save();first.reject(Error('offline'));await saving;assert.equal(m.rules.alert_cpu,true);assert.equal(m.rulesError,'offline');assert.equal(calls,1);await m.save();assert.equal(calls,2);assert.equal(m.rulesError,'');
});

test('numeric rules cannot write invalid thresholds and release their save lock on failure',async()=>{
 let calls=0;const {c}=setup(async()=>{calls++;throw Error('offline');});const m=c.alertManager();m.loaded=true;m.wpSecCfg.threshold=0;await m.saveWPSecCfg();assert.equal(calls,0);assert.equal(m.wpSecSaving,false);assert.equal(m.wpSecError,'followup.invalid_threshold');m.wpSecCfg.threshold=10;await m.saveWPSecCfg();assert.equal(calls,1);assert.equal(m.wpSecError,'offline');assert.equal(m.wpSecSaving,false);
});

test('logs distinguish failed loading from an empty successful result',async()=>{
 let fail=true;const {c}=setup(async()=>{if(fail)throw Error('log unavailable');return ok([]);});const m=c.alertManager();await m.fetchLog();assert.equal(m.logsLoaded,false);assert.equal(m.logsError,'log unavailable');fail=false;await m.fetchLog();assert.equal(m.logsLoaded,true);assert.equal(m.logsError,'');assert.equal(m.logsLoading,false);
});


test('the rule count includes existing boolean rules without serializing numeric security settings',async()=>{
 const d={...data(),alert_site:'true',alert_wp_code_integrity:'true'};let body;const {c}=setup(async(url,opt)=>{if(opt?.method){body=opt.body;return ok({});}return ok(url==='/alert/log'?[]:d);});const m=c.alertManager();await m.fetchAll();assert.equal(m.rules.alert_site,true);assert.equal(m.rules.alert_wp_code_integrity,true);await m.save();assert.equal(body.alert_site,'true');assert.equal(body.alert_wp_security_threshold,undefined);
});

test('saving an empty SMTP port displays the effective default without leaving a false dirty state',async()=>{
 const {c}=setup(async(url,opt)=>ok(opt?.method?{}:data()));const m=c.smtpConfig();await m.fetch();m.cfg.smtp_port='';await m.save();assert.equal(m.cfg.smtp_port,'587');assert.equal(m.dirty(),false);
});
