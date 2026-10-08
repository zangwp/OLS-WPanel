const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const { test } = require('node:test');
const source = fs.readFileSync(path.join(__dirname, '../../web/templates/remote_backup_settings.html'), 'utf8').match(/<script>([\s\S]*?)<\/script>/)[1];
const ok = data => ({success:true,data});
const defer = () => { let resolve,reject;const promise=new Promise((a,b)=>{resolve=a;reject=b;});return {promise,resolve,reject}; };
const config = () => ({enabled:true,backup_type:'rsync',connection_mode:'auto',server_id:'test',host:'backup.example.com',port:22,username:'backup_test',auth_type:'key',remote_path:'/mnt/backup/ols-wpanel/test',remote_base_path:'/mnt/backup',isolate_path:true,keep_local:true,s3_endpoint:'',s3_bucket:'',s3_region:'auto',s3_access_key_id:'',s3_path_prefix:'ols-wpanel/test',s3_base_prefix:'ols-wpanel',ssh_key:'ssh-ed25519 AAAATEST fixture'});
function setup(api,extra={}){const toasts=[];const c={api,t:k=>k,showToast:(...a)=>toasts.push(a),...extra};vm.createContext(c);vm.runInContext(source,c);return {m:c.remoteBackup(),toasts};}

test('failed or malformed remote configuration never permits save, test or commands',async()=>{
 let fail=true,malformed=false,writes=0;const {m}=setup(async(url,opt)=>{if(opt?.method){writes++;return ok({});}if(fail)throw Error('offline');return ok(malformed?{enabled:false}:config());});await m.fetchRemote();await m.saveRemote();await m.testConnection();assert.equal(m.loaded,false);assert.equal(m.loadError,'offline');assert.equal(m.canCopyCmd(),false);assert.equal(writes,0);fail=false;malformed=true;await m.fetchRemote();await m.saveRemote();assert.equal(m.loadError,'followup.invalid_config');assert.equal(writes,0);malformed=false;await m.fetchRemote();assert.equal(m.loaded,true);assert.equal(m.loadError,'');assert.equal(m.cfg.password,'');assert.equal(m.cfg.s3_secret_key,'');assert.equal(m.canCopyCmd(),true);
});

test('remote save locks duplicate operations and sends an immutable snapshot',async()=>{
 const pending=defer(),writes=[];let gets=0;const {m}=setup(async(url,opt)=>{if(opt?.method){writes.push(opt.body);return pending.promise;}gets++;return ok(config());});await m.fetchRemote();m.cfg.host='submitted.example.com';const saving=m.saveRemote();m.cfg.host='changed.example.com';await m.saveRemote();await m.testConnection();await m.fetchRemote();assert.equal(writes.length,1);assert.equal(writes[0].host,'submitted.example.com');assert.equal(gets,1);pending.resolve(ok({}));await saving;assert.equal(m.saving,false);assert.equal(m.loaded,true);assert.equal(m.dirty(),false);assert.equal(gets,2);
});

test('successful remote save with failed reload remains saved but blocks further edits',async()=>{
 let reads=0;const {m}=setup(async(url,opt)=>{if(opt?.method)return ok({});if(++reads===1)return ok(config());throw Error('reload unavailable');});await m.fetchRemote();await m.saveRemote();assert.equal(m.saveOK,true);assert.equal(m.saveMsg,'followup.saved_reload_failed');assert.equal(m.loaded,false);assert.equal(m.canCopyCmd(),false);assert.equal(m.loadError,'reload unavailable');assert.equal(m.saving,false);
});

test('save failure preserves user edits and never reports saved',async()=>{
 const {m}=setup(async(url,opt)=>opt?.method?{success:false,message:'disk full'}:ok(config()));await m.fetchRemote();m.cfg.host='edited.example.com';await m.saveRemote();assert.equal(m.saveOK,false);assert.equal(m.saveMsg,'disk full');assert.equal(m.cfg.host,'edited.example.com');assert.equal(m.dirty(),true);assert.equal(m.saving,false);
});

test('connection tests and setup or deletion commands require the saved configuration',async()=>{
 let writes=0;const {m}=setup(async(url,opt)=>{if(opt?.method)writes++;return ok(config());});await m.fetchRemote();m.cfg.host='unsaved.example.com';await m.testConnection();assert.equal(writes,0);assert.equal(m.canCopyCmd(),false);m.helperMode='delete';assert.equal(m.canCopyCmd(),false);await m.fetchRemote();await m.testConnection();assert.equal(writes,1);assert.equal(m.testOK,true);
});

test('setup commands quote saved path and SSH public key and group fallback operations',async()=>{
 const d=config();d.remote_base_path="/mnt/backup space's";d.remote_path=d.remote_base_path+'/ols-wpanel/test';d.ssh_key="ssh-ed25519 AAAATEST user's key";const {m}=setup(async()=>ok(d));await m.fetchRemote();const cmd=m.genCmd();assert.ok(cmd.includes("mkdir -p -- '/mnt/backup space'\"'\"'s/ols-wpanel/test'"));assert.ok(cmd.includes("user'\"'\"'s key"));assert.ok(cmd.includes('(grep -qxF --'));assert.ok(cmd.includes("printf '%s\\n'"));
});

test('failed clipboard fallback never claims the command was copied',async()=>{
 const {m,toasts}=setup(async()=>ok(config()),{navigator:{clipboard:{writeText:async()=>{throw Error('denied');}}},document:{createElement:()=>({select(){},remove(){}}),body:{appendChild(){}},execCommand:()=>false}});await m.fetchRemote();await m.copyCmd();assert.equal(toasts.at(-1)[1],'error');assert.equal(toasts.some(t=>t[1]==='success'),false);
});
