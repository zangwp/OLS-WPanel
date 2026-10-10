const fs = require('node:fs'), path = require('node:path'), vm = require('node:vm'), assert = require('node:assert/strict');
const source = [...fs.readFileSync(path.resolve(__dirname, '../../web/templates/backups.html'), 'utf8').matchAll(/<script[^>]*>([\s\S]*?)<\/script>/g)].map(m => m[1]).join('\n');
const deferred = () => { let resolve, reject; const promise = new Promise((ok, fail) => { resolve = ok; reject = fail; }); return {promise, resolve, reject}; };
function fixture() {
  const timers = new Map(), calls = [], toasts = []; let timerID = 0;
  const site = {site_id:1, domain:'one.example.com', db_backups:[
    {id:11, filename:'new.sql.gz', local_exists:true}, {id:12, filename:'old.sql.gz', local_exists:true}, {id:13, filename:'remote.sql.gz', local_exists:false}
  ], file_backups:[{id:21, filename:'increment.tar.gz', mode:'incremental', local_exists:true},
    {id:22, filename:'full.tar.gz', mode:'full', local_exists:true}, {id:23, filename:'remote.tar.gz', mode:'full', local_exists:false}]};
  const ctx = {t:(key, values) => key + (values ? JSON.stringify(values) : ''), fmtTime:value=>value || '', formatBytes:String,
    confirmModal:async()=>true, showToast:(...args)=>toasts.push(args), window:{}, document:{},
    setTimeout:fn=>{timers.set(++timerID, fn); return timerID;}, clearTimeout:id=>timers.delete(id)};
  let handler = async url => {
    if (url === '/backups/overview') return {success:true, data:{sites:[site], panel_db_backups:[]}};
    if (url.endsWith('/active-restore')) return {success:true, data:{active:false}};
    throw Error('Unexpected API: ' + url);
  };
  ctx.api = async (url, options) => { calls.push({url, options}); return handler(url, options); };
  vm.createContext(ctx); vm.runInContext(source, ctx);
  const model = ctx.backupsOverview();
  return {ctx, model, site, calls, timers, toasts, handler(fn){handler=fn;}, async tick(){const pair=timers.entries().next().value; assert(pair, 'poll timer'); timers.delete(pair[0]); await pair[1]();}};
}
async function main() {
  {
    const f=fixture(); await f.model.fetchOverview();
    assert.equal(f.model.dbSelections[1],11); assert.equal(f.model.fileSelections[1],22, 'default to local full');
    assert.equal(f.model.siteBusy(f.site), false);
    f.model.dbSelections[1]=12; f.model.fileSelections[1]=21; await f.model.fetchOverview();
    assert.equal(f.model.dbSelections[1],12); assert.equal(f.model.fileSelections[1],21);
    assert.equal(f.model.canRestoreFile(f.site),false); await f.model.restoreSelected(f.site,'file');
    f.model.fileSelections[1]=23; await f.model.restoreSelected(f.site,'file');
    f.model.dbSelections[1]=13; await f.model.restoreSelected(f.site,'db');
    assert(!f.calls.some(c=>c.options?.method==='POST'),'unrestorable backups never submit');
    f.handler(async()=>{throw Error('offline');}); await f.model.fetchOverview();
    assert(f.model.overviewError); assert(f.model.siteBusy(f.site)); assert.equal(f.model.sites.length,1,'keep previous data');
  }
  {
    const f=fixture(); await f.model.fetchOverview(); const confirm=deferred(), post=deferred(); f.ctx.confirmModal=()=>confirm.promise;
    let statusReads=0;
    f.handler(async(url, opts)=>{
      if(opts?.method==='POST') return post.promise;
      if(url.endsWith('/restore-tasks/task-db')) return {success:true,data:{task_id:'task-db',status:++statusReads===1?'running':'success',success:statusReads>1,message:'restored'}};
      if(url==='/backups/overview') return {success:true,data:{sites:[f.site],panel_db_backups:[]}};
      throw Error('unexpected '+url);
    });
    const pending=f.model.restoreSelected(f.site,'db'); assert(f.model.siteBusy(f.site));
    await f.model.restoreSelected(f.site,'file'); assert.equal(f.calls.filter(c=>c.options?.method==='POST').length,0);
    f.model.dbSelections[1]=12; confirm.resolve(true); await new Promise(resolve=>setImmediate(resolve));
    assert.equal(f.calls.filter(c=>c.options?.method==='POST').length,1);
    assert.equal(f.calls.find(c=>c.options?.method==='POST').url,'/websites/1/backups/11/restore','snapshot selection before confirmation');
    await f.model.restoreSelected(f.site,'db'); assert.equal(f.calls.filter(c=>c.options?.method==='POST').length,1);
    post.resolve({success:true,data:{task_id:'task-db'}}); await pending;
    assert.equal(f.model.restoreStates[1].phase,'running'); assert(f.model.siteBusy(f.site));
    await f.tick(); assert.equal(f.model.restoreStates[1].phase,'success'); assert(!f.model.siteBusy(f.site)); assert.equal(f.toasts.length,1);
  }
  {
    const f=fixture(); await f.model.fetchOverview();
    f.ctx.confirmModal=async()=>false; await f.model.restoreSelected(f.site,'db'); assert(!f.model.restoreStates[1]);
    f.ctx.confirmModal=async()=>true;
    f.handler(async()=>{const e=Error('conflict'); e.status=409; throw e;});
    await f.model.restoreSelected(f.site,'file'); assert.equal(f.model.restoreStates[1].phase,'failed'); assert(!f.model.siteBusy(f.site));
    f.handler(async()=>{throw Error('connection lost');}); await f.model.restoreSelected(f.site,'file');
    assert.equal(f.model.restoreStates[1].phase,'unknown'); assert(f.model.siteBusy(f.site));
    f.handler(async(url)=>({success:true,data:{active:true,kind:'file',task_id:'file-task',status:'running',success:false}}));
    await f.model.resumeSiteRestore(f.site); assert.equal(f.model.restoreStates[1].task_id,'file-task'); assert.equal(f.model.restoreStates[1].phase,'running');
    assert.equal(f.calls.at(-1).url,'/websites/1/file-backups/restore-tasks/file-task');
    f.handler(async()=>({success:true,data:{task_id:'file-task',status:'success',success:false}}));
    await f.tick(); assert.equal(f.model.restoreStates[1].phase,'unknown','inconsistent success is never success'); assert.equal(f.toasts.length,0);
    f.handler(async()=>{const e=Error('gone'); e.status=404; throw e;});
    await f.model.resumeSiteRestore(f.site); assert.equal(f.model.restoreStates[1].phase,'failed'); assert.equal(f.timers.size,0,'gone task stops polling');
  }
  {
    const f=fixture(); await f.model.fetchOverview();
    f.model.restoreStates[1]={phase:'unknown',task_id:''};
    f.handler(async()=>({success:true,data:{active:false}})); await f.model.resumeSiteRestore(f.site);
    assert.equal(f.model.restoreStates[1].phase,'failed'); assert.equal(f.model.restoreStates[1].message,'backups.restore_no_active_task');
    delete f.model.restoreStates[1];
    f.handler(async(url)=>url.endsWith('/active-restore') ? {success:true,data:{active:true,kind:'db',task_id:'resumed',status:'waiting'}} : {success:true,data:{task_id:'resumed',status:'running'}});
    await f.model.resumeSiteRestore(f.site); assert(f.model.siteBusy(f.site)); assert.equal(f.timers.size,1);
    const late=deferred(); f.handler(()=>late.promise); const poll=f.model.pollSiteRestore(f.site,f.model.restoreStates[1]);
    f.model.destroy(); assert.equal(f.timers.size,0); late.resolve({success:true,data:{task_id:'resumed',status:'success',success:true}}); await poll;
    assert.equal(f.model.restoreStates[1].phase,'running'); assert.equal(f.toasts.length,0,'destroy ignores late completion');
  }
  {
    const f=fixture(); await f.model.fetchOverview();
    const old=deferred(), latest=deferred(); let calls=0;
    f.handler(url=>url.endsWith('/active-restore') ? (++calls===1?old.promise:latest.promise) : Promise.reject(Error('unexpected')));
    const first=f.model.resumeSiteRestore(f.site), second=f.model.resumeSiteRestore(f.site);
    latest.resolve({success:true,data:{active:false}}); await second;
    old.resolve({success:true,data:{active:true,kind:'file',task_id:'stale',status:'running'}}); await first;
    assert.equal(f.model.restoreStates[1].task_id,'','late status cannot replace newer state');
    const overview1=deferred(), overview2=deferred(); calls=0;
    f.handler(url=>url==='/backups/overview' ? (++calls===1?overview1.promise:overview2.promise) : Promise.resolve({success:true,data:{active:false}}));
    const a=f.model.fetchOverview(), b=f.model.fetchOverview();
    overview2.resolve({success:true,data:{sites:[],panel_db_backups:[]}}); await b;
    overview1.resolve({success:true,data:{sites:[f.site],panel_db_backups:[]}}); await a;
    assert.equal(f.model.sites.length,0,'stale overview cannot reset newer list');
  }
  console.log('PASS backup restore state: scoped selection, admission, polling, uncertain outcomes, resumed tasks, teardown and stale responses');
}
main().catch(error=>{console.error(error);process.exitCode=1;});
