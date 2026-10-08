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
