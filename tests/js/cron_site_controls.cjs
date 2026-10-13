const fs = require('node:fs'), vm = require('node:vm'), assert = require('node:assert/strict');
const source = fs.readFileSync('web/templates/cron.html', 'utf8').match(/<script>([\s\S]*?)<\/script>/)[1].replace(/{{[\s\S]*?}}/g, 'translated');
function setup() {
    const calls = [], prompts = [], toasts = [];
    const ctx = {
        window: {}, t: (key, params) => ({key, params}),
        api: async (url, options) => { calls.push({url, options}); return {success: true, data: []}; },
        confirmModal: async message => { prompts.push(message); return true; },
        showToast: (message, type) => toasts.push({message, type}),
    };
    vm.createContext(ctx); vm.runInContext(source, ctx);
    return {ctx, manager: ctx.cronManager(), systemManager: ctx.systemCronManager(), calls, prompts, toasts};
}
function deferred() {
    let resolve;
    const promise = new Promise(done => { resolve = done; });
    return {promise, resolve};
}
function wpJob(overrides = {}) {
    return {id: 7, task_type: 'wp_cron', name: '[wp_cron] example.com', enabled: false, running: false, ...overrides};
}
(async () => {
    {
        const {ctx, systemManager: manager} = setup();
        assert.equal(manager.sysLoading, true);
        for (const failure of ['response', 'network', 'malformed']) {
            const previous = [{source: '/etc/crontab', schedule: '0 2 * * *', command: 'saved-task'}];
            manager.sysJobs = previous;
            ctx.api = async url => {
                assert.equal(url, '/cron/system');
                if (failure === 'network') throw new Error('HTTP 503');
                if (failure === 'malformed') return {success: true, data: null};
                return {success: false, message: 'HTTP 503'};
            };
            await manager.fetchSysCron();
            assert.ok(manager.sysError);
            assert.equal(manager.sysJobs, previous);
            assert.equal(manager.sysLoading, false);
        }
        ctx.api = async () => ({success: true, data: []});
        await manager.fetchSysCron();
        assert.equal(manager.sysError, '');
        assert.equal(manager.sysJobs.length, 0);
        assert.equal(manager.sysLoading, false);
    }
    {
        const {ctx, systemManager: manager} = setup(), first = deferred(), second = deferred();
        let reads = 0; ctx.api = () => ++reads === 1 ? first.promise : second.promise;
        const older = manager.fetchSysCron(), newer = manager.fetchSysCron();
        assert.equal(manager.sysLoading, true);
        second.resolve({success: true, data: [{command: 'latest-task'}]}); await newer;
        first.resolve({success: false, message: 'stale failure'}); await older;
        assert.equal(manager.sysJobs[0].command, 'latest-task');
        assert.equal(manager.sysError, '');
        assert.equal(manager.sysLoading, false);
    }
    {
        const {ctx, manager, calls} = setup();
        const job = {id: 3, task_type: 'command', name: 'Custom command', enabled: true};
        manager.jobs = [job];
        ctx.api = async (url, options) => { calls.push({url,options}); throw new Error('offline'); };
        await manager.fetchList();
        calls.length = 0;
        assert.equal(manager.listError, 'offline');
        assert.equal(manager.jobs[0], job);
        await manager.runJob(job); await manager.deleteJob(job); manager.openEdit(job);
        assert.equal(calls.length, 0); assert.equal(manager.showModal, false);
        ctx.api = async (url, options) => { calls.push({url,options}); return {success:true,data:[job]}; };
        await manager.fetchList(); assert.equal(manager.listError, '');
        calls.length = 0;
        for (const runtime_reason of ['backup_maintenance', 'ownership_error', 'migration_locked']) {
            await manager.runJob({...job,runtime_suspended:true,runtime_reason});
        }
        assert.equal(calls.length, 0);
        ctx.api = async () => ({success:true,data:null});
        await manager.fetchList(); assert.ok(manager.listError); assert.equal(manager.jobs[0], job);
    }
    {
        const {ctx, manager} = setup(), first = deferred(), second = deferred();
        let reads=0;ctx.api=()=>++reads===1?first.promise:second.promise;
        const older=manager.fetchList(), newer=manager.fetchList();
        second.resolve({success:true,data:[{id:2}]});await newer;
        first.resolve({success:true,data:[{id:1}]});await older;
        assert.equal(manager.jobs[0].id,2);assert.equal(manager.loading,false);
    }
    {
        const {manager, calls, prompts} = setup();
        for (const enabled of [true, undefined, null, 0, 'false']) {
            const job = wpJob({enabled});
            assert.equal(manager.canDeleteJob(job), false);
            await manager.deleteJob(job);
            await manager.runJob(job);
        }
        await manager.deleteJob(wpJob({running: true}));
        assert.equal(calls.length, 0);
        assert.equal(prompts.length, 0);
    }
    {
        const {ctx, manager, calls, prompts, toasts} = setup(), confirm = deferred(), deleted = deferred();
        const job = wpJob(); manager.jobs = [job];
        ctx.confirmModal = async message => { prompts.push(message); return confirm.promise; };
        ctx.api = async (url, options) => {
            calls.push({url, options});
            return options ? deleted.promise : {success: true, data: []};
        };
        const first = manager.deleteJob(job);
        await manager.deleteJob(job);
        assert.equal(prompts.length, 1);
        assert.equal(prompts[0].key, 'cron.confirm_delete_wp_cron');
        assert.equal(prompts[0].params.name, 'example.com');
        assert.equal(calls.length, 0);
        assert.equal(manager.deletingId, job.id);
        confirm.resolve(true);
        await new Promise(done => setImmediate(done));
        await manager.deleteJob(job);
        assert.equal(calls.length, 1);
        assert.equal(calls[0].url, '/cron/7?require_disabled=true');
        assert.equal(calls[0].options.method, 'DELETE');
        deleted.resolve({success: true}); await first;
        assert.equal(calls.length, 2);
        assert.equal(calls[1].url, '/cron');
        assert.equal(manager.jobs.length, 0);
        assert.equal(manager.deletingId, null);
        assert.equal(toasts.length, 1);
        assert.equal(toasts[0].type, 'success');
    }
    for (const change of ['cancel', 'enabled', 'running']) {
        const {ctx, manager, calls, toasts} = setup(), job = wpJob();
        ctx.confirmModal = async () => {
            if (change !== 'cancel') job[change] = true;
            return change !== 'cancel';
        };
        await manager.deleteJob(job);
        assert.equal(calls.length, 0);
        assert.equal(toasts.length, 0);
        assert.equal(manager.deletingId, null);
    }
    for (const failure of ['response', 'network']) {
        const {ctx, manager, toasts} = setup(), job = wpJob(); manager.jobs = [job];
        ctx.api = async () => {
            if (failure === 'network') throw new Error('offline');
            return {success: false, message: 'Task is running'};
        };
        await manager.deleteJob(job);
        assert.equal(manager.jobs.length, 1);
        assert.equal(manager.deletingId, null);
        assert.equal(toasts.length, 1);
        assert.equal(toasts[0].type, 'error');
    }
    {
        const {manager, prompts, calls} = setup();
        await manager.deleteJob({id: 3, task_type: 'command', name: 'Custom command', enabled: true});
        assert.equal(prompts[0].key, 'cron.confirm_delete');
        assert.equal(calls[0].url, '/cron/3');
        assert.equal(calls[0].options.method, 'DELETE');
    }
    console.log('PASS cron controls: only explicitly disabled WP-Cron records can be deleted; confirmation, running-state and duplicate guards, refresh and failure handling verified');
})().catch(error => { console.error(error); process.exit(1); });
