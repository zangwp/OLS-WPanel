const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const { test } = require('node:test');

const source = fs.readFileSync(path.join(__dirname, '../../web/templates/software.html'), 'utf8')
    .match(/<script>([\s\S]*?)<\/script>/)[1].replace(/{{[\s\S]*?}}/g, 'translated');
const deferred = () => {
    let resolve, reject;
    const promise = new Promise((yes, no) => { resolve = yes; reject = no; });
    return { promise, resolve, reject };
};
function setup(overrides = {}) {
    const timers = new Map();
    let nextTimer = 0;
    const context = {
        AbortController,
        t: key => key, showToast() {}, confirmModal: async () => true,
        setTimeout: callback => { timers.set(++nextTimer, callback); return nextTimer; },
        clearTimeout: id => timers.delete(id),
        api: async () => ({ success: true, data: [{ service: 'lsws', name: 'OpenLiteSpeed' }] }),
        ...overrides,
    };
    vm.createContext(context);
    vm.runInContext(source, context);
    return { context, timers };
}

for (const name of ['PHP', 'MariaDB']) {
    test(`${name}: edits made during a save remain unsaved and can be submitted next`, async () => {
        const firstSave = deferred(), calls = [];
        const { context } = setup({ api: (url, options) => {
            calls.push({ url, body: options.body });
            return calls.length === 1 ? firstSave.promise : Promise.resolve({ success: true });
        } });
        const manager = context.softwareManager();
        const cfg = { key: 'memory_limit', value: '128M', _value: '256M' };
        const software = { name, configs: [cfg] };
        const saving = manager.saveConfig(software);
        cfg._value = '512M';
        assert.equal(software._saving, true);
        firstSave.resolve({ success: true });
        await saving;
        assert.equal(cfg.value, '256M');
        assert.equal(cfg._value, '512M');
        assert.equal(software._saving, false);
        await manager.saveConfig(software);
        assert.equal(calls.length, 2);
        assert.equal(name === 'PHP' ? calls[1].body.values.memory_limit : calls[1].body.value, '512M');
        assert.equal(cfg.value, '512M');
    });
}

test('failed save retains the last confirmed baseline and allows retry', async () => {
    const { context } = setup({ api: async () => { throw new Error('reload failed'); } });
    const cfg = { key: 'memory_limit', value: '128M', _value: '256M' };
    const software = { name: 'PHP', configs: [cfg] };
    await context.softwareManager().saveConfig(software);
    assert.equal(cfg.value, '128M');
    assert.equal(cfg._value, '256M');
    assert.equal(software._saving, false);
});

test('service actions maintain one polling chain and destroy cancels it', async () => {
    const { context, timers } = setup();
    const guard = context.processGuard();
    await guard.fetchStatus();
    assert.equal(timers.size, 1);
    await guard.action('lsws', 'restart');
    await guard.action('lsws', 'restart');
    assert.equal(timers.size, 1);
    assert.equal(guard.services[0]._acting, false);
    guard.destroy();
    assert.equal(timers.size, 0);
    await guard.fetchStatus();
    assert.equal(timers.size, 0);
});

test('manual guard refresh bypasses only version cache and ordinary polls keep the default URL', async () => {
    const calls = [];
    const { context, timers } = setup({ api: async url => {
        calls.push(url);
        return { success: true, data: [] };
    } });
    const guard = context.processGuard();
    await guard.fetchStatus(true);
    await guard.fetchStatus();
    assert.deepEqual(calls, ['/software/guard?fresh=1', '/software/guard']);
    assert.equal(timers.size, 1);
    guard.destroy();
});

test('late status responses cannot overwrite new status or restart polling after destroy', async () => {
    const old = deferred(), latest = deferred();
    let count = 0;
    const { context, timers } = setup({ api: () => (++count === 1 ? old.promise : latest.promise) });
    const guard = context.processGuard();
    const first = guard.fetchStatus(), second = guard.fetchStatus();
    latest.resolve({ success: true, data: [{ service: 'lsws', status: 'running' }] });
    await second;
    old.resolve({ success: true, data: [{ service: 'lsws', status: 'stopped' }] });
    await first;
    assert.equal(guard.services[0].status, 'running');
    assert.equal(timers.size, 1);
    const pending = deferred();
    context.api = () => pending.promise;
    const inFlight = guard.fetchStatus();
    guard.destroy();
    pending.resolve({ success: true, data: [] });
    await inFlight;
    assert.equal(timers.size, 0);
    assert.equal(guard.services[0].status, 'running');
});

test('background status refresh preserves an in-flight service action', async () => {
    const action = deferred();
    const { context } = setup();
    const guard = context.processGuard();
    await guard.fetchStatus();
    context.api = async url => url.endsWith('/action') ? action.promise : ({ success: true, data: [{ service: 'lsws' }] });
    const running = guard.action('lsws', 'start');
    await guard.fetchStatus();
    assert.equal(guard.services[0]._acting, true);
    action.resolve({ success: true });
    await running;
    assert.equal(guard.services[0]._acting, false);
    guard.destroy();
});

test('environment checks keep the latest response and cancel reads on destroy', async () => {
    const old = deferred(), latest = deferred(), calls = [];
    const { context } = setup({ api: (url, options) => { calls.push({ url, options }); return calls.length === 1 ? old.promise : latest.promise; } });
    const manager = context.softwareManager();
    const first = manager.fetchHealth(), second = manager.fetchHealth(true);
    assert.equal(calls[0].options.signal.aborted, true);
    assert.equal(calls[1].url, '/software/health?fresh=1');
    latest.resolve({ success: true, data: { checked_at: 'latest', php: [] } });
    await second;
    old.resolve({ success: true, data: { checked_at: 'old' } });
    await first;
    assert.equal(manager.health.checked_at, 'latest');
    const pending = deferred();
    context.api = () => pending.promise;
    const third = manager.fetchHealth();
    manager.destroy();
    pending.resolve({ success: true, data: { checked_at: 'disposed' } });
    await third;
    assert.equal(manager.health.checked_at, 'latest');
});

test('failed health checks preserve previous evidence with an explicit error', async () => {
    const { context } = setup({ api: async () => { throw Error('unavailable'); } });
    const manager = context.softwareManager();
    manager.health = { checked_at: 'last-success' };
    await manager.fetchHealth(true);
    assert.equal(manager.health.checked_at, 'last-success');
    assert.equal(manager.healthError, 'unavailable');
    assert.equal(manager.healthLoading, false);
    assert.equal(manager.healthFresh, false);
});

test('PHP health separates required failures from recommended omissions and unknown checks', () => {
    const { context } = setup({ t: (key, values) => values ? `${key}:${values.count}` : key });
    const manager = context.softwareManager();
    manager.health = { php: [{ version: '8.5', state: 'warning', extensions: [
        { name: 'curl', importance: 'recommended', state: 'missing' },
        { name: 'hash', importance: 'required', state: 'loaded' },
        { name: 'mysqli', importance: 'required', state: 'missing' },
        { name: 'json', importance: 'required', state: 'loaded' },
    ] }] };
    assert.equal(manager.extensionSummary('8.5', 'required'), 'software.extensions_required_missing:1');
    assert.equal(manager.extensionSummary('8.5', 'recommended'), 'software.extensions_recommended_missing:1');
    assert.match(manager.extensionSummaryBadge('8.5', 'required'), /badge-warning/);
    assert.match(manager.extensionSummaryBadge('8.5', 'recommended'), /badge-info/);
    assert.deepEqual(Array.from(manager.healthExtensions('8.5'), extension => extension.name), ['mysqli', 'hash', 'json', 'curl']);
    manager.health.php[0].extensions.find(extension => extension.name === 'mysqli').state = 'loaded';
    assert.equal(manager.extensionSummary('8.5', 'required'), 'software.extensions_required_ready:3');
    manager.health.php[0].state = 'unknown';
    assert.equal(manager.runtimeHealthKnown('8.5'), false);
    assert.equal(manager.extensionSummary('8.5', 'required'), 'software.health_unknown');
    assert.equal(manager.extensionSummary('8.5', 'recommended'), 'software.health_unknown');
    assert.equal(manager.extensionSummary('8.3', 'required'), 'software.health_unknown');
});

test('PHP version display puts the configured default first without changing its assignment', () => {
    const { context } = setup();
    const manager = context.softwareManager();
    manager.phpRuntimes = [
        { version: '8.5', active_sites: 0 },
        { version: '8.4', active_sites: 4 },
        { version: '8.3', primary: true, active_sites: 1 },
    ];
    assert.deepEqual(Array.from(manager.orderedPHPRuntimes(), runtime => runtime.version), ['8.3', '8.4', '8.5']);
    assert.deepEqual(Array.from(manager.phpRuntimes, runtime => runtime.version), ['8.5', '8.4', '8.3']);
    assert.equal(manager.phpRuntimes[2].primary, true);
});

test('PHP completion needs fresh missing-extension evidence and uses a repair confirmation', async () => {
    const calls = [], prompts = [];
    const { context } = setup({ confirmModal: async message => { prompts.push(message); return true; }, api: async (url, options) => { calls.push({url, options}); return {success:true,data:[]}; } });
    const manager = context.softwareManager(), runtime = {version:'8.3',installed:true,active_sites:0};
    manager.health = {php:[{version:'8.3',state:'warning',extensions:[{name:'curl',importance:'recommended',state:'missing'}]}]};
    assert.equal(manager.canRepairPHPRuntime(runtime), false);
    manager.healthFresh = true;
    assert.equal(manager.canRepairPHPRuntime(runtime), true);
    manager.healthError = 'offline'; assert.equal(manager.canRepairPHPRuntime(runtime), false);
    manager.healthError = ''; manager.healthLoading = true; assert.equal(manager.canRepairPHPRuntime(runtime), false);
    manager.healthLoading = false;
    await manager.installPHPRuntime(runtime);
    assert.equal(prompts[0], 'software.php_runtime_repair_confirm');
    assert.equal(calls[0].url, '/software/php-runtimes/install');
    assert.equal(calls[0].options.body.version, '8.3');
});

test('backup repair requires current successful evidence and stops after a failed refresh', async () => {
    const calls = [], read = deferred();
    const { context } = setup({ api: url => { calls.push(url); return read.promise; } });
    const manager = context.softwareManager();
    manager.health = { checked_at: 'last-success', backup: { status: 'missing', configuration_status: 'ok', missing_required: ['mysql'], dependencies: [
        { id: 'mysql', package: 'mariadb-client-compat', status: 'missing', required: true },
    ] } };
    assert.equal(manager.canRepairBackupDependencies(), false);
    manager.healthFresh = true;
    assert.equal(manager.canRepairBackupDependencies(), true);
    const refreshing = manager.fetchHealth(true);
    assert.equal(manager.canRepairBackupDependencies(), false);
    await manager.installBackupDependencies();
    assert.equal(calls.length, 1);
    read.reject(Error('check failed'));
    await refreshing;
    assert.equal(manager.health.checked_at, 'last-success');
    assert.equal(manager.canRepairBackupDependencies(), false);
    assert.equal(manager.backupCurrentState(), 'unknown');
    await manager.installBackupDependencies();
    assert.equal(calls.length, 1);
});

test('fresh unknown required tools block repair and optional tools never trigger it', () => {
    const { context } = setup();
    const manager = context.softwareManager();
    manager.healthFresh = true;
    manager.health = { backup: { status: 'missing', configuration_status: 'ok', missing_required: ['mysql'], dependencies: [
        { id: 'mysql', package: 'mariadb-client-compat', status: 'missing', required: true },
        { id: 'gzip', package: 'gzip', status: 'error', required: true },
        { id: 'sshpass', package: 'sshpass', status: 'missing', required: false },
    ] } };
    assert.equal(manager.canRepairBackupDependencies(), false);
    manager.health.backup.dependencies[1].status = 'installed';
    assert.equal(manager.canRepairBackupDependencies(), true);
    manager.health.backup.dependencies[0].status = 'installed';
    manager.health.backup.status = 'installed';
    assert.equal(manager.canRepairBackupDependencies(), false);
    assert.deepEqual(Array.from(manager.missingDependencyPackages()), []);
});

test('backup repair rechecks state after confirmation instead of acting on superseded evidence', async () => {
    const confirmation = deferred(), calls = [];
    const { context } = setup({ confirmModal: () => confirmation.promise, api: async url => { calls.push(url); return { success: true }; } });
    const manager = context.softwareManager();
    manager.healthFresh = true;
    manager.health = { backup: { status: 'missing', configuration_status: 'ok', missing_required: ['mysql'], dependencies: [
        { id: 'mysql', package: 'mariadb-client-compat', status: 'missing', required: true },
    ] } };
    const operation = manager.installBackupDependencies();
    manager.healthFresh = false;
    confirmation.resolve(true);
    await operation;
    assert.equal(calls.length, 0);
    assert.equal(manager.dependencyInstalling, false);
});

test('environment summaries distinguish backup readiness, cron startup and stale results', async () => {
    const { context } = setup({ api: async () => ({ success: true, data: {
        checked_at: 'latest', backup: { status: 'installed' }, cron: { state: 'running', enabled: 'enabled' },
    } }) });
    const manager = context.softwareManager();
    await manager.fetchHealth(true);
    assert.equal(manager.healthFresh, true);
    assert.equal(manager.backupSummary(), 'software.backup_required_ready');
    assert.equal(manager.cronSummary(), 'software.cron_ready');
    manager.health.cron.enabled = 'disabled';
    assert.equal(manager.cronSummary(), 'software.cron_autostart_attention');
    manager.healthFresh = false;
    assert.equal(manager.backupSummary(), 'software.backup_check_unknown');
    assert.equal(manager.cronSummary(), 'software.cron_check_unknown');
});

test('dependency installation considers only currently required missing tools and refreshes on failure', async () => {
    const calls = [];
    const { context } = setup({ api: async (url, options) => {
        calls.push({ url, options });
        if (url.endsWith('/install')) throw Error('apt failed');
        return { success: true, data: { backup: { missing_required: [], dependencies: [] } } };
    } });
    const manager = context.softwareManager();
    manager.healthFresh = true;
    manager.health = { backup: { status: 'missing', configuration_status: 'ok', missing_required: ['mysql', 'mysqldump'], dependencies: [
        { id: 'mysql', package: 'mariadb-client-compat', status: 'missing', required: true },
        { id: 'mysqldump', package: 'mariadb-client-compat', status: 'missing', required: true },
        { id: 'rsync', package: 'rsync', status: 'missing', required: false },
    ] } };
    assert.deepEqual(Array.from(manager.missingDependencyPackages()), ['mariadb-client-compat']);
    await manager.installBackupDependencies();
    assert.equal(calls[0].url, '/software/backup-dependencies/install');
    assert.equal(calls[0].options.method, 'POST');
    assert.equal(calls[1].url, '/software/health?fresh=1');
    assert.equal(manager.dependencyInstalling, false);
    manager.health.backup.configuration_status = 'error';
    await manager.installBackupDependencies();
    assert.equal(calls.length, 2);
});

for (const kind of ['runtime', 'tool']) {
    test(`${kind}: refreshing during installation does not leave the new row busy`, async () => {
        const installation = deferred(), started = deferred();
        const { context } = setup({ api: async url => {
            if (url.endsWith('/install')) { started.resolve(); return installation.promise; }
            if (url.endsWith('/php-runtimes')) return { success: true, data: [{ version: '8.4', installed: true }] };
            if (url.endsWith('/development-tools')) return { success: true, data: [{ id: 'wp-cli', state: 'installed' }] };
            return { success: true, data: [] };
        } });
        const manager = context.softwareManager();
        const row = kind === 'runtime' ? { version: '8.4' } : { id: 'wp-cli', name: 'WP-CLI', state: 'missing' };
        if (kind === 'runtime') manager.phpRuntimes = [row]; else manager.developmentTools = [row];
        const operation = kind === 'runtime' ? manager.installPHPRuntime(row) : manager.installDevelopmentTool(row);
        await started.promise;
        if (kind === 'runtime') await manager.fetchPHPRuntimes(); else await manager.fetchDevelopmentTools();
        const current = kind === 'runtime' ? manager.phpRuntimes[0] : manager.developmentTools[0];
        assert.equal(current._installing, true);
        installation.resolve({ success: true });
        await operation;
        assert.equal((kind === 'runtime' ? manager.phpRuntimes[0] : manager.developmentTools[0])._installing, false);
    });
}

test('failed tool installation refreshes observed state and clears only its own progress', async () => {
    const calls = [];
    const { context } = setup({ api: async url => {
        calls.push(url);
        if (url.endsWith('/install')) throw Error('connection interrupted after publication');
        return { success: true, data: [{ id: 'wp-cli', state: 'installed' }, { id: 'nodejs', state: 'missing' }] };
    } });
    const manager = context.softwareManager();
    const wp = { id: 'wp-cli', name: 'WP-CLI', state: 'missing' };
    manager.developmentTools = [wp, { id: 'nodejs', state: 'missing', _installing: true }];
    await manager.installDevelopmentTool(wp);
    assert.deepEqual(calls, ['/software/development-tools/install', '/software/development-tools']);
    assert.equal(manager.developmentTools[0].state, 'installed');
    assert.equal(manager.developmentTools[0]._installing, false);
    assert.equal(manager.developmentTools[1]._installing, true);
});

test('failed runtime repair refreshes the extension catalog and health before clearing progress', async () => {
    const calls = [];
    const { context } = setup({ api: async url => {
        calls.push(url);
        if (url.endsWith('/install')) throw Error('connection interrupted after package installation');
        if (url.endsWith('/php-runtimes')) return { success: true, data: [{ version: '8.3', installed: true }] };
        return { success: true, data: {} };
    } });
    const manager = context.softwareManager();
    const runtime = { version: '8.3', installed: true };
    manager.phpRuntimes = [runtime];
    await manager.installPHPRuntime(runtime);
    assert.deepEqual(calls, ['/software/php-runtimes/install', '/software/php-runtimes', '/software/health?fresh=1']);
    assert.equal(manager.phpRuntimes[0].installed, true);
    assert.equal(manager.phpRuntimes[0]._installing, false);
    assert.equal(manager.healthFresh, true);
});

test('leaving software while tool installation finishes suppresses late notices and reads', async () => {
    const installation = deferred(), started = deferred(), calls = [], notices = [];
    const { context } = setup({ showToast: (...args) => notices.push(args), api: async url => {
        calls.push(url);
        started.resolve();
        return installation.promise;
    } });
    const manager = context.softwareManager();
    const wp = { id: 'wp-cli', name: 'WP-CLI', state: 'missing' };
    manager.developmentTools = [wp];
    const operation = manager.installDevelopmentTool(wp);
    await started.promise;
    manager.destroy();
    installation.resolve({ success: true });
    await operation;
    assert.deepEqual(calls, ['/software/development-tools/install']);
    assert.equal(notices.length, 0);
    assert.equal(wp._installing, false);
});

test('software refresh retains unsaved tuning values', async () => {
    const { context } = setup({ api: async url => ({ success: true, data: url.startsWith('/software?') ? [
        { name: 'PHP', configs: [{ key: 'memory_limit', value: '256M' }] }
    ] : [] }) });
    const manager = context.softwareManager();
    manager.software = [{ name: 'PHP', configs: [{ key: 'memory_limit', value: '256M', _value: '512M' }] }];
    await manager.fetchList(true);
    assert.equal(manager.software[0].configs[0]._value, '512M');
    assert.equal(manager.software[0].configs[0].value, '256M');
});

test('runtime catalog failure preserves the last list and retry clears its independent error', async () => {
    const calls = [];
    const {context} = setup({api:async(url, options)=>{calls.push({url,options});throw Error('catalog offline');}});
    const manager=context.softwareManager();manager.phpRuntimes=[{version:'8.5',installed:true}];manager.runtimeLoaded=true;
    await manager.fetchPHPRuntimes();
    assert.equal(manager.runtimeError,'catalog offline');assert.equal(manager.runtimeLoading,false);
    assert.equal(manager.phpRuntimes[0].version,'8.5');assert.equal(manager.healthError,'');assert.equal(manager.listError,'');
    await manager.installPHPRuntime({version:'8.4'});assert.equal(calls.length,1,'unknown inventory must not trigger installation');
    context.api=async()=>({success:true,data:[]});await manager.fetchPHPRuntimes();
    assert.equal(manager.runtimeLoaded,true);assert.equal(manager.runtimeError,'');assert.equal(manager.phpRuntimes.length,0);
});

test('invalid runtime data is a retryable failure rather than an empty successful catalog', async()=>{
    const {context}=setup({api:async()=>({success:true,data:null})});const manager=context.softwareManager();
    await manager.fetchPHPRuntimes();assert(manager.runtimeError);assert.equal(manager.runtimeLoaded,false);
    context.api=async()=>({success:true,data:[{version:'8.5'}]});await manager.fetchPHPRuntimes();
    assert.equal(manager.runtimeError,'');assert.equal(manager.phpRuntimes[0].version,'8.5');
});

test('an old runtime failure cannot overwrite a fresh read and destroy aborts the catalog request',async()=>{
    const old=deferred(),latest=deferred();let count=0;const calls=[];
    const {context}=setup({api:(url,options)=>{calls.push(options);return ++count===1?old.promise:latest.promise;}});const manager=context.softwareManager();
    const first=manager.fetchPHPRuntimes(),second=manager.fetchPHPRuntimes();
    assert.equal(calls[0].signal.aborted,true);latest.resolve({success:true,data:[{version:'8.5'}]});await second;
    old.reject(Error('old catalog failure'));await first;assert.equal(manager.runtimeError,'');assert.equal(manager.runtimeLoading,false);
    const pending=deferred();context.api=()=>pending.promise;const read=manager.fetchPHPRuntimes();manager.destroy();
    pending.resolve({success:true,data:[]});await read;assert.equal(manager.phpRuntimes[0].version,'8.5');
});

test('guard errors remain independent and preserve old rows until an explicit successful retry',async()=>{
    const calls=[];const {context,timers}=setup({api:async(url,options)=>{calls.push({url,options});throw Error('service status offline');}});const guard=context.processGuard();
    guard.services=[{service:'lsws',name:'OpenLiteSpeed',running:true}];guard.statusLoaded=true;
    await guard.fetchStatus();assert.equal(guard.statusError,'service status offline');assert.equal(guard.services[0].running,true);assert.equal(guard.statusLoading,false);
    await guard.action('lsws','stop');assert.equal(calls.length,1,'unverified old service status must not authorize an action');assert.equal(timers.size,1);
    context.api=async()=>({success:true,data:[]});await guard.fetchStatus(true);
    assert.equal(guard.statusError,'');assert.equal(guard.statusLoaded,true);assert.equal(guard.services.length,0);assert.equal(timers.size,1);guard.destroy();
});

test('old guard failure cannot clear current loading or replace the latest result',async()=>{
    const old=deferred(),latest=deferred();let count=0;const {context}=setup({api:()=>++count===1?old.promise:latest.promise});const guard=context.processGuard();
    const first=guard.fetchStatus(),second=guard.fetchStatus(true);old.reject(Error('late stale error'));await first;
    assert.equal(guard.statusLoading,true);assert.equal(guard.statusError,'');latest.resolve({success:true,data:[{service:'lsws'}]});await second;
    assert.equal(guard.statusLoaded,true);assert.equal(guard.statusLoading,false);assert.equal(guard.statusError,'');guard.destroy();
});

test('guard malformed data cannot erase its last verified services',async()=>{
    const {context}=setup({api:async()=>({success:true,data:{}})});const guard=context.processGuard();guard.services=[{service:'lsws'}];
    await guard.fetchStatus();assert(guard.statusError);assert.equal(guard.services[0].service,'lsws');assert.equal(guard.statusLoaded,false);guard.destroy();
});

test('OPcache unknown metrics and disabled configuration are never reported as measured zeros', () => {
    const { context } = setup();
    const manager = context.softwareManager();
    manager.health = { php: [{ version: '8.5', state: 'ok', opcache: { enabled: false, memory_mb: null } }] };
    assert.equal(manager.opcacheValue('8.5', 'enabled'), 'software.health_disabled');
    assert.equal(manager.opcacheValue('8.5', 'memory_mb'), 'software.health_unknown');
    assert.equal(manager.healthLabel('error'), 'software.health_failed');
});

test('an OPcache ABI failure explains the error without treating extensions as missing or enabling repair', () => {
    const translations = [];
    const { context } = setup({ t: (key, values) => { translations.push({ key, values }); return key; } });
    const manager = context.softwareManager();
    manager.healthFresh = true;
    manager.health = { php: [{ version: '8.3', state: 'error', reason: 'extension_abi_mismatch',
        diagnostic: { code: 'extension_abi_mismatch', extension: 'opcache', symbol: 'zend_handle_delayed_oom' },
        extensions: [{ name: 'opcache', importance: 'recommended', state: 'unknown' }],
        opcache: { configuration_state: 'unknown', enabled: null },
    }] };
    assert.equal(manager.phpHealthReason(manager.runtimeHealth('8.3').reason), 'software.php_extension_abi_mismatch');
    assert.equal(manager.phpHealthDiagnostic('8.3'), 'software.php_extension_abi_detail');
    assert.equal(translations.at(-1).values.extension, 'opcache');
    assert.equal(translations.at(-1).values.symbol, 'zend_handle_delayed_oom');
    assert.equal(manager.runtimeHealthKnown('8.3'), false);
    assert.equal(manager.canRepairPHPRuntime({ version: '8.3', installed: true }), false);
    assert.equal(manager.extensionSummary('8.3', 'recommended'), 'software.health_unknown');
    assert.equal(manager.healthLabel(manager.runtimeHealth('8.3').state), 'software.health_failed');
    assert.equal(manager.opcacheValue('8.3', 'enabled'), 'software.health_unknown');
    assert.equal(manager.phpHealthDiagnostic('8.5'), '');
});
