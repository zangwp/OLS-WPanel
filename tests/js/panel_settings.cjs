const fs=require('fs'),vm=require('vm'),assert=require('assert'),path=require('path');
process.chdir(path.resolve(__dirname,'../..'));
function code(file){return [...fs.readFileSync('static/templates/'+file,'utf8').matchAll(/<script[^>]*>([\s\S]*?)<\/script>/g)].map(x=>x[1].replace(/{{[\s\S]*?}}/g,'null')).join('\n');}
const ctx={t:k=>k,showToast:()=>{},api:async()=>({success:true,data:{recommendations:{innodb_buffer_pool_size:'512M'}}})};vm.createContext(ctx);vm.runInContext(code('software.html'),ctx);
(async()=>{
 const sw={name:'MariaDB',configs:[{key:'innodb_buffer_pool_size',value:'742M',_value:'600M'}]};await ctx.softwareManager().recommend(sw);assert.equal(sw.configs[0]._value,'600M');assert.equal(sw.configs[0]._recommended,'512M');assert.equal(sw.configs[0].value,'742M');
 vm.runInContext(code('website_detail.html'),ctx);const name=code('website_detail.html').match(/function (\w+)\(/)[1];let page=ctx[name]();page.site={id:1,domain:'example.com'};let posts=0;ctx.api=async(path,opts)=>{if(opts){posts++;return {success:true}}return {success:true,data:[{id:7,site_id:1,task_type:'wp_cron',enabled:false,cron_expression:'*/5 * * * *'}]}};await page.createWPCron();assert.equal(posts,0);assert.equal(page.wpCronJobs.length,1);
 let body;ctx.api=async(path,opts)=>{if(opts){body=opts.body;throw Error('failed')}return {success:true,data:[{id:7,site_id:1,task_type:'wp_cron',enabled:true,cron_expression:'*/5 * * * *'}]}};await page.saveWPCron({...page.wpCronJobs[0],name:'job'},false);assert.equal(body.enabled,false);assert.equal(page.wpCronJobs[0].enabled,true);assert.equal(page.wpCronBusy,false);
 ctx.api=async()=>{throw Error('unavailable')};await page.loadSSLRenewal();assert.equal(page.sslRenewalLoaded,false);assert(page.sslRenewalError);
 console.log('PASS: recommendation preserves edits, existing site tasks reused, failed task changes reload server state, renewal load failure disables editing');
})().catch(e=>{console.error(e);process.exit(1)});
