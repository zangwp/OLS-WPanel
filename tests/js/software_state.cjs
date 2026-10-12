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
});

test('dependency installation considers only currently required missing tools and refreshes on failure', async () => {
    const calls = [];
    const { context } = setup({ api: async (url, options) => {
        calls.push({ url, options });
        if (url.endsWith('/install')) throw Error('apt failed');
        return { success: true, data: { backup: { missing_required: [], dependencies: [] } } };
    } });
    const manager = context.softwareManager();
    manager.health = { backup: { configuration_status: 'ok', missing_required: ['mysql', 'mysqldump'], dependencies: [
        { id: 'mysql', package: 'mariadb-client', status: 'missing', required: true },
        { id: 'mysqldump', package: 'mariadb-client', status: 'missing', required: true },
        { id: 'rsync', package: 'rsync', status: 'missing', required: false },
    ] } };
    assert.deepEqual(Array.from(manager.missingDependencyPackages()), ['mariadb-client']);
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
        const installation = deferred();
        const { context } = setup({ api: async url => {
            if (url.endsWith('/install')) return installation.promise;
            if (url.endsWith('/php-runtimes')) return { success: true, data: [{ version: '8.4', installed: true }] };
            if (url.endsWith('/development-tools')) return { success: true, data: [{ id: 'wp-cli', state: 'installed' }] };
            return { success: true, data: [] };
        } });
        const manager = context.softwareManager();
        const row = kind === 'runtime' ? { version: '8.4' } : { id: 'wp-cli', name: 'WP-CLI', state: 'missing' };
        if (kind === 'runtime') manager.phpRuntimes = [row]; else manager.developmentTools = [row];
        const operation = kind === 'runtime' ? manager.installPHPRuntime(row) : manager.installDevelopmentTool(row);
        await Promise.resolve(); await Promise.resolve();
        if (kind === 'runtime') await manager.fetchPHPRuntimes(); else await manager.fetchDevelopmentTools();
        const current = kind === 'runtime' ? manager.phpRuntimes[0] : manager.developmentTools[0];
        assert.equal(current._installing, true);
        installation.resolve({ success: true });
        await operation;
        assert.equal((kind === 'runtime' ? manager.phpRuntimes[0] : manager.developmentTools[0])._installing, false);
    });
}

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

test('OPcache unknown metrics and disabled configuration are never reported as measured zeros', () => {
    const { context } = setup();
    const manager = context.softwareManager();
    manager.health = { php: [{ version: '8.5', state: 'ok', opcache: { enabled: false, memory_mb: null } }] };
    assert.equal(manager.opcacheValue('8.5', 'enabled'), 'software.health_disabled');
    assert.equal(manager.opcacheValue('8.5', 'memory_mb'), 'software.health_unknown');
    assert.equal(manager.healthLabel('error'), 'software.health_failed');
});
