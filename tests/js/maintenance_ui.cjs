const fs=require('node:fs'),vm=require('node:vm'),assert=require('node:assert/strict');
function script(file){return [...fs.readFileSync('web/templates/'+file,'utf8').matchAll(/<script[^>]*>([\s\S]*?)<\/script>/g)].map(m=>m[1].replace(/{{[\s\S]*?}}/g,'translated')).join('\n');}
let calls=[];const ctx={t:x=>x,showToast:()=>{},confirmModal:async()=>true,api:async p=>{calls.push(p);return {success:true,data:p==='/software'?[{name:'MariaDB',configs:[{key:'innodb_buffer_pool_size',value:'742M'}]}]:[]};}};
vm.createContext(ctx);vm.runInContext(script('software.html'),ctx);
(async()=>{
 let page=ctx.softwareManager();await page.fetchList();assert(!calls.some(x=>x.includes('/recommend')));assert.equal(page.software[0]._showRecommendations,false);
 let sw=page.software[0];sw.configs[0]._value='600M';ctx.api=async()=>({success:true,data:{recommendations:{innodb_buffer_pool_size:'742M'}}});await page.recommend(sw);assert.equal(sw.configs[0]._value,'600M');assert.equal(sw._showRecommendations,true);
 ctx.api=async()=>{throw Error('status unavailable')};await page.fetchDevelopmentTools();assert.equal(page.toolsError,'status unavailable');assert.equal(page.developmentTools.length,0);assert.equal(page.toolsLoading,false);
 ctx.api=async()=>{throw Error('must not install')};await page.installDevelopmentTool({state:'error'});

 let phpRefreshes=0;page.fetchPHPRuntimes=async()=>{phpRefreshes++};page.fetchDevelopmentTools=async()=>{};
 ctx.api=async()=>({success:true,data:[]});const runtime={version:'8.4',_installing:false};await page.installPHPRuntime(runtime);assert.equal(phpRefreshes,1,'successful installation refreshes PHP runtimes once');assert.equal(runtime._installing,false);
 console.log('On-demand suggestions preserve input; tool errors cannot install.');
})().catch(e=>{console.error(e);process.exit(1)});
