const fs=require('node:fs'),vm=require('node:vm'),assert=require('node:assert/strict');
const source=fs.readFileSync('web/templates/cron.html','utf8').match(/<script>([\s\S]*?)<\/script>/)[1].replace(/{{[\s\S]*?}}/g,'translated');
const ctx={window:{},t:x=>x,api:async()=>{throw Error('site task must be managed from site settings')},confirmModal:async()=>{throw Error('site task cannot prompt for deletion')},showToast:()=>{}};
vm.createContext(ctx);vm.runInContext(source,ctx);
(async()=>{const p=ctx.cronManager();await p.runJob({task_type:'wp_cron'});await p.deleteJob({task_type:'wp_cron'});console.log('Site-owned WordPress tasks cannot run or delete through overview actions');})().catch(e=>{console.error(e);process.exit(1)});
