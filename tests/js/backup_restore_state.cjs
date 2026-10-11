const fs = require('node:fs'), path = require('node:path'), vm = require('node:vm'), assert = require('node:assert/strict');
const source = [...fs.readFileSync(path.resolve(__dirname, '../../web/templates/backups.html'), 'utf8').matchAll(/<script[^>]*>([\s\S]*?)<\/script>/g)].map(m => m[1]).join('\n');
const deferred = () => { let resolve, reject; const promise = new Promise((ok, fail) => { resolve = ok; reject = fail; }); return {promise, resolve, reject}; };
function fixture() {
  const timers = new Map(), calls = [], toasts = []; let timerID = 0;
  const site = {site_id:1, domain:'one.example.com', status:'active', site_type:'wordpress', document_root_subdir:'', site_backups:[
    {id:'11111111-1111-4111-8111-111111111111', created_at:'2026-10-10T02:00:00Z', state:'complete', local_exists:true, requires_attention:false, consistency:'controlled_quiescence', db_size:1024, file_size:2048},
    {id:'22222222-2222-4222-8222-222222222222', created_at:'2026-10-09T02:00:00Z', state:'incomplete', local_exists:true, requires_attention:true, consistency:'controlled_quiescence'},
    {id:'33333333-3333-4333-8333-333333333333', created_at:'2026-10-08T02:00:00Z', state:'complete', local_exists:false, requires_attention:false, consistency:'controlled_quiescence'}
  ], db_backups:[
    {id:11, filename:'new.sql.gz', local_exists:true}, {id:12, filename:'old.sql.gz', local_exists:true}, {id:13, filename:'remote.sql.gz', local_exists:false}
  ], file_backups:[{id:21, filename:'increment.tar.gz', mode:'incremental', local_exists:true},
    {id:22, filename:'full.tar.gz', mode:'full', local_exists:true}, {id:23, filename:'remote.tar.gz', mode:'full', local_exists:false}]};
  const ctx = {t:(key, values) => key + (values ? JSON.stringify(values) : ''), fmtTime:value=>value || '', formatBytes:String,
    confirmModal:async()=>true, showToast:(...args)=>toasts.push(args), window:{}, document:{},
    setTimeout:fn=>{timers.set(++timerID, fn); return timerID;}, clearTimeout:id=>timers.delete(id)};
  let handler = async url => {
    if (url === '/backups/overview') return {success:true, data:{sites:[site], panel_db_backups:[]}};
    if (url.endsWith('/active-operation')) return {success:true, data:{active:false}};
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
    f.model.restoreStates[1]={kind:'file',phase:'unknown',task_id:''};
    f.handler(async()=>({success:true,data:{active:false}})); await f.model.resumeSiteRestore(f.site);
    assert.equal(f.model.restoreStates[1].phase,'failed'); assert.equal(f.model.restoreStates[1].message,'backups.restore_no_active_task');
    delete f.model.restoreStates[1];
    f.handler(async(url)=>url.endsWith('/active-operation') ? {success:true,data:{active:true,kind:'db',task_id:'resumed',status:'waiting'}} : {success:true,data:{task_id:'resumed',status:'running'}});
    await f.model.resumeSiteRestore(f.site); assert(f.model.siteBusy(f.site)); assert.equal(f.timers.size,1);
    const late=deferred(); f.handler(()=>late.promise); const poll=f.model.pollSiteRestore(f.site,f.model.restoreStates[1]);
    f.model.destroy(); assert.equal(f.timers.size,0); late.resolve({success:true,data:{task_id:'resumed',status:'success',success:true}}); await poll;
    assert.equal(f.model.restoreStates[1].phase,'running'); assert.equal(f.toasts.length,0,'destroy ignores late completion');
  }
  {
    const f=fixture(); await f.model.fetchOverview();
    const old=deferred(), latest=deferred(); let calls=0;
    f.handler(url=>url.endsWith('/active-operation') ? (++calls===1?old.promise:latest.promise) : Promise.reject(Error('unexpected')));
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
  {
    const f=fixture(); await f.model.fetchOverview();
    assert.equal(f.model.siteSelections[1], f.site.site_backups[0].id); assert(f.model.canRestoreSite(f.site));
    for (const backup of f.site.site_backups.slice(1)) {
      f.model.siteSelections[1]=backup.id; assert(!f.model.canRestoreSite(f.site)); await f.model.startSiteOperation(f.site,'site_restore');
    }
    f.model.siteSelections[1]=f.site.site_backups[0].id;
    for (const change of [{requires_attention:true}, {consistency:'timestamp_matched'}, {consistency:undefined}]) {
      const original={...f.site.site_backups[0]}; Object.assign(f.site.site_backups[0],change);
      assert(!f.model.canRestoreSite(f.site),'needs verified consistency and no attention'); await f.model.startSiteOperation(f.site,'site_restore');
      f.site.site_backups[0]=original;
    }
    f.site.site_backups_error='manifest read failed'; assert(!f.model.canRestoreSite(f.site)); await f.model.startSiteOperation(f.site,'site_restore');
    delete f.site.site_backups_error;
    for (const change of [{status:'paused'}, {site_type:'php'}, {document_root_subdir:'public'}, {status:'backup_maintenance'}]) {
      const original={status:f.site.status,site_type:f.site.site_type,document_root_subdir:f.site.document_root_subdir}; Object.assign(f.site,change);
      assert(!f.model.canRestoreSite(f.site)); await f.model.startSiteOperation(f.site,'site_restore'); await f.model.startSiteOperation(f.site,'site_backup'); Object.assign(f.site,original);
    }
    assert(!f.calls.some(c=>c.options?.method==='POST'),'missing components, incomplete sets and ineligible sites never submit');
    f.site.site_backups=[]; f.site.db_backups[0].created_at=f.site.file_backups[1].created_at='2026-10-10T02:00:00Z';
    await f.model.fetchOverview(); assert.equal(f.model.siteSelections[1],''); assert(!f.model.canRestoreSite(f.site),'even equal timestamps never synthesize a point');
  }
  {
    const f=fixture(); await f.model.fetchOverview(); const confirm=deferred(), post=deferred(); f.ctx.confirmModal=()=>confirm.promise;
    let reads=0;
    f.handler(async(url,opts)=>{
      if(opts?.method==='POST') return post.promise;
      if(url.endsWith('/backups/tasks/whole-restore')) return {success:true,data:{kind:'site_restore',task_id:'whole-restore',status:++reads===1?'running':'success',success:reads>1}};
      if(url==='/backups/overview') return {success:true,data:{sites:[f.site],panel_db_backups:[]}};
      throw Error('unexpected '+url);
    });
    const pending=f.model.startSiteOperation(f.site,'site_restore'); assert(f.model.siteBusy(f.site));
    f.model.siteSelections[1]=f.site.site_backups[2].id; await f.model.startSiteOperation(f.site,'file_backup');
    confirm.resolve(true); await new Promise(resolve=>setImmediate(resolve));
    const admission=f.calls.find(c=>c.options?.method==='POST'); assert.equal(admission.url,'/websites/1/site-backups/'+f.site.site_backups[0].id+'/restore','snapshot exact point before confirmation');
    assert.deepEqual(JSON.parse(JSON.stringify(admission.options.body)),{confirm_restore:true,external_writers_stopped:true});
    post.resolve({success:true,data:{kind:'site_restore',task_id:'whole-restore'}}); await pending;
    assert.equal(f.model.restoreStates[1].phase,'running'); assert.equal(f.toasts.length,0,'admission is not restoration success');
    await f.tick(); assert.equal(f.model.restoreStates[1].phase,'success'); assert.equal(f.toasts.length,1);
  }
  {
    const f=fixture(); await f.model.fetchOverview(); f.ctx.confirmModal=async()=>false;
    await f.model.startSiteOperation(f.site,'site_backup'); assert(!f.model.restoreStates[1]); assert(!f.calls.some(c=>c.options?.method==='POST'));
    f.ctx.confirmModal=async()=>true; let reads=0;
    f.handler(async(url,opts)=>{
      if(opts?.method==='POST') return {success:true,data:{task_id:'whole-backup',kind:'site_backup'}};
      if(url.endsWith('/backups/tasks/whole-backup')) {
        if (++reads===1) return {success:true,data:{task_id:'whole-backup',kind:'site_backup',status:'waiting',success:false}};
        f.site.site_backups.unshift({...f.site.site_backups[0],id:'44444444-4444-4444-8444-444444444444'});
        return {success:true,data:{task_id:'whole-backup',kind:'site_backup',status:'success',success:true}};
      }
      if(url==='/backups/overview') return {success:true,data:{sites:[f.site],panel_db_backups:[]}};
      throw Error('unexpected '+url);
    });
    await f.model.startSiteOperation(f.site,'site_backup');
    const admission=f.calls.find(c=>c.options?.method==='POST'); assert.equal(admission.url,'/websites/1/site-backups');
    assert.deepEqual(JSON.parse(JSON.stringify(admission.options.body)),{confirm_maintenance:true,external_writers_stopped:true});
    assert.equal(f.toasts.length,0); await f.tick(); assert.equal(f.model.siteSelections[1],f.site.site_backups[0].id,'select newly completed point');
  }
  {
    const f=fixture(); await f.model.fetchOverview();
    f.handler(async()=>{throw Error('POST response lost');}); await f.model.startSiteOperation(f.site,'site_restore');
    assert.equal(f.model.restoreStates[1].phase,'unknown'); assert(f.model.siteBusy(f.site));
    f.handler(async(url)=>url.endsWith('/active-operation') ? {success:true,data:{active:true,kind:'site_restore',task_id:'lost-task',status:'running'}} :
      {success:true,data:{task_id:'lost-task',kind:'site_restore',status:'running',success:false}});
    await f.model.resumeSiteRestore(f.site); assert.equal(f.model.restoreStates[1].task_id,'lost-task');
    assert.equal(f.calls.at(-1).url,'/websites/1/backups/tasks/lost-task');
    f.handler(async()=>({success:true,data:{task_id:'lost-task',kind:'site_backup',status:'success',success:true}}));
    await f.tick(); assert.equal(f.model.restoreStates[1].phase,'unknown','other task kind cannot prove success'); assert.equal(f.toasts.length,0);
    f.handler(async()=>({success:true,data:{task_id:'lost-task',kind:'site_restore',status:'success',success:false}}));
    await f.model.resumeSiteRestore(f.site); assert.equal(f.model.restoreStates[1].phase,'unknown','inconsistent terminal result remains locked');
    f.handler(async()=>({success:true,data:{task_id:'lost-task',kind:'site_restore',status:'failed',success:true}}));
    await f.model.resumeSiteRestore(f.site); assert.equal(f.model.restoreStates[1].phase,'unknown','inconsistent failure cannot unlock controls');
    f.model.restoreStates[1]={kind:'site_restore',phase:'unknown',task_id:''};
    f.handler(async()=>({success:true,data:{active:false}})); await f.model.resumeSiteRestore(f.site);
    assert.equal(f.model.restoreStates[1].phase,'failed'); assert.equal(f.model.restoreStates[1].message,'backups.operation_no_active_task'); assert.equal(f.toasts.length,0,'absence of active task is not success');
  }
  {
    const f=fixture(); await f.model.fetchOverview(); let confirmations=0; f.ctx.confirmModal=async()=>{confirmations++;return true;};
    f.handler(async(url,opts)=> opts?.method==='POST' ? {success:true,data:{kind:'file_backup',task_id:'files-now'}} :
      {success:true,data:{kind:'file_backup',task_id:'files-now',status:'running',success:false}});
    await f.model.startSiteOperation(f.site,'file_backup'); assert.equal(confirmations,0,'single file backup does not imply maintenance');
    assert.equal(f.calls.find(c=>c.options?.method==='POST').url,'/websites/1/file-backups'); assert(f.model.siteBusy(f.site));
    assert(!f.calls.some(c=>c.url.includes('/cron')),'one-off file backup never creates a schedule');
    const loaded=fixture(); loaded.handler(async(url)=> url==='/backups/overview' ? {success:true,data:{sites:[loaded.site],panel_db_backups:[]}} :
      url.endsWith('/active-operation') ? {success:true,data:{active:true,kind:'db_backup',task_id:'existing-db-create',status:'running'}} :
      {success:true,data:{kind:'db_backup',task_id:'existing-db-create',status:'running',success:false}});
    await loaded.model.fetchOverview(); assert(loaded.model.siteBusy(loaded.site)); assert.equal(loaded.model.restoreStates[1].kind,'db_backup');
  }
  {
    const f=fixture(); await f.model.fetchOverview(); let downloads=[]; f.ctx.document.body={dataset:{panelPrefix:'/preview'}}; f.ctx.window.open=url=>downloads.push(url);
    f.model.downloadSiteBackup(f.site,'files'); f.model.downloadSiteBackup(f.site,'database'); f.model.downloadSiteBackup(f.site,'unexpected');
    assert.equal(downloads.length,2); assert(downloads.every(url=>url.includes('/site-backups/'+f.site.site_backups[0].id+'/download?component=')),'both downloads belong to the selected point');
    const confirm=deferred(); f.ctx.confirmModal=()=>confirm.promise;
    f.handler(async(url,opts)=>opts?.method==='DELETE' ? {success:true,data:{}} : {success:true,data:{sites:[f.site],panel_db_backups:[]}});
    const removal=f.model.deleteSiteBackup(f.site); assert(f.model.siteBusy(f.site)); f.model.siteSelections[1]=f.site.site_backups[2].id;
    confirm.resolve(true); await removal;
    assert.equal(f.calls.find(c=>c.options?.method==='DELETE').url,'/websites/1/site-backups/'+f.site.site_backups[0].id,'delete snapshot removes exact set only');
    f.model.downloadSiteBackup(f.site,'files'); assert.equal(downloads.length,2,'missing local component cannot download');
    f.model.restoreStates[1]={kind:'site_restore',task_id:'failed-restore',phase:'running'}; f.site.status='backup_maintenance';
    f.handler(async(url)=>url.endsWith('/tasks/failed-restore') ? {success:true,data:{kind:'site_restore',task_id:'failed-restore',status:'failed',success:false,message:'restore failed; safety copy retained'}} :
      (f.site.status='active',{success:true,data:{sites:[f.site],panel_db_backups:[]}}));
    await f.model.pollSiteRestore(f.site,f.model.restoreStates[1]); assert.equal(f.model.restoreStates[1].phase,'failed'); assert.equal(f.site.status,'active');
    assert.equal(f.model.restoreStates[1].message,'restore failed; safety copy retained'); assert(!f.model.siteBusy(f.site),'terminal error refreshes actual maintenance state');
    assert.equal(f.toasts.filter(toast=>toast[1]==='success').length,1,'only the successful deletion was toasted');
  }
  {
    const f=fixture(); f.site.status='backup_maintenance'; await f.model.fetchOverview();
    assert(f.model.siteBusy(f.site)); assert(f.model.canRecoverMaintenance(f.site),'explicitly inactive operation permits guarded maintenance recovery');
    f.ctx.confirmModal=async()=>false; await f.model.recoverSiteMaintenance(f.site);
    assert(!f.calls.some(c=>c.options?.method==='POST')); assert(!f.model.maintenanceRecoveryStates[1]);
    f.handler(async()=>({success:true,data:{active:'false'}})); await f.model.checkMaintenanceEligibility(f.site);
    assert(!f.model.canRecoverMaintenance(f.site),'malformed active status cannot authorize recovery');
    f.handler(async()=>({success:true,data:{active:true,kind:'site_restore',task_id:'other-task',status:'running'}})); await f.model.checkMaintenanceEligibility(f.site);
    assert(!f.model.canRecoverMaintenance(f.site),'active worker cannot be thawed');
    f.handler(async()=>({success:true,data:{active:false}})); await f.model.checkMaintenanceEligibility(f.site);
    f.model.restoreStates[1]={kind:'site_restore',phase:'unknown',task_id:'uncertain'};
    assert(!f.model.canRecoverMaintenance(f.site),'an unresolved task outcome still prevents maintenance recovery');
  }
  {
    const f=fixture(); f.site.status='backup_maintenance'; const oldState={kind:'site_restore',phase:'failed',task_id:'original',message:'original restore failed'};
    f.model.restoreStates[1]=oldState; await f.model.fetchOverview();
    const confirmation=deferred(), response=deferred(); f.ctx.confirmModal=()=>confirmation.promise;
    f.handler(async(url,opts)=>{
      if(opts?.method==='POST') return response.promise;
      if(url==='/backups/overview') return {success:true,data:{sites:[f.site],panel_db_backups:[]}};
      if(url.endsWith('/active-operation')) return {success:true,data:{active:false}};
      throw Error('unexpected '+url);
    });
    const recovery=f.model.recoverSiteMaintenance(f.site); assert(f.model.siteBusy(f.site)); assert(!f.model.canRecoverMaintenance(f.site));
    await f.model.recoverSiteMaintenance(f.site); confirmation.resolve(true); await new Promise(resolve=>setImmediate(resolve));
    const admission=f.calls.find(c=>c.options?.method==='POST'); assert.equal(admission.url,'/websites/1/site-backups/recover-maintenance');
    assert.equal(admission.options.timeout,150000); assert.deepEqual(JSON.parse(JSON.stringify(admission.options.body)),{confirm_recovery:true});
    assert.equal(f.toasts.length,0); f.site.status='active'; response.resolve({success:true,data:{maintenance_recovered:true,message:'access restored'}}); await recovery;
    assert.equal(f.model.maintenanceRecoveryStates[1].phase,'success'); assert.equal(f.model.restoreStates[1],oldState,'recovering access never changes failed restore result');
    assert.equal(f.toasts.length,1); assert.equal(f.toasts[0][0],'access restored');
  }
  {
    const f=fixture(); f.site.status='backup_maintenance'; const oldState={kind:'site_restore',phase:'failed',task_id:'failed-old',message:'failed snapshot remains'};
    f.model.restoreStates[1]=oldState; await f.model.fetchOverview();
    f.handler(async(url,opts)=>{
      if(opts?.method==='POST'){const e=Error('partial state; maintenance retained'); e.status=409; throw e;}
      if(url==='/backups/overview') return {success:true,data:{sites:[f.site],panel_db_backups:[]}};
      return {success:true,data:{active:false}};
    });
    await f.model.recoverSiteMaintenance(f.site); assert.equal(f.model.maintenanceRecoveryStates[1].phase,'failed'); assert.equal(f.site.status,'backup_maintenance');
    assert.equal(f.model.restoreStates[1],oldState); assert.equal(f.toasts.length,0);
    f.handler(async(url,opts)=>{
      if(opts?.method==='POST'){f.site.status='active'; throw Error('response lost after thaw');}
      if(url==='/backups/overview') return {success:true,data:{sites:[f.site],panel_db_backups:[]}};
      return {success:true,data:{active:false}};
    });
    await f.model.recoverSiteMaintenance(f.site); assert.equal(f.model.maintenanceRecoveryStates[1].phase,'unknown'); assert(f.model.siteBusy(f.site),'lost recovery response remains locked even if cached site status changes');
    await f.model.recheckMaintenanceRecovery(f.site); assert.equal(f.model.maintenanceRecoveryStates[1].phase,'checked'); assert(!f.model.siteBusy(f.site));
    assert.equal(f.model.restoreStates[1],oldState); assert.equal(f.toasts.length,0,'readonly active status never claims restore or recovery request success');
  }
  console.log('PASS backup restore state: existing single-item safety, complete whole-site sets, async tasks and guarded maintenance access recovery');
}
main().catch(error=>{console.error(error);process.exitCode=1;});
