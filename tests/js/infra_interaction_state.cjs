const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const {test} = require('node:test');

const deferred = () => {
    let resolve, reject;
    const promise = new Promise((yes, no) => { resolve = yes; reject = no; });
    return {promise, resolve, reject};
};
const ok = data => ({success: true, data});
const tick = () => new Promise(resolve => setImmediate(resolve));
function setup(file, factory) {
    const html = fs.readFileSync(path.join(__dirname, '../../web/templates', file), 'utf8');
    const source = [...html.matchAll(/<script[^>]*>([\s\S]*?)<\/script>/g)].map(match => match[1]).join('\n');
    const calls = [];
    const context = {
        AbortController, URL, URLSearchParams, setTimeout: () => 1, clearTimeout() {},
        t: key => key, showToast() {}, confirmModal: async () => true,
        window: {location: {pathname: '/panel/databases/1'}, history: {replaceState() {}}},
        document: {querySelector: () => null, body: {dataset: {}}},
        api: async (url, options = {}) => { calls.push({url, options}); throw Error('unexpected request: ' + url); },
    };
    vm.createContext(context); vm.runInContext(source, context);
    const page = context[factory](); page.$nextTick = callback => callback(); page.$dispatch = () => {};
    return {page, context, html, calls};
}
function buttonExpression(html, click, attr, page) {
    const button = [...html.matchAll(/<button\b[^>]*>/g)].map(match => match[0]).find(tag => tag.includes(`@click="${click}"`));
    assert(button, `missing button ${click}`);
    const expression = button.match(new RegExp(`${attr}="([^"]+)"`))?.[1];
    assert(expression, `missing ${attr} on ${click}`);
    return vm.runInNewContext(expression, {...page, t: key => key});
}

test('DB sync shows only its own progress, preserves prefix edits and refreshes only database metadata', async () => {
    const {page, context, html} = setup('database_detail.html', 'databaseDetail');
    page.site = {id: 1, table_prefix: 'wp_'}; page.editTablePrefix = 'wp_'; page.loading = false;
    const mutation = deferred(), read = deferred(), calls = [];
    context.api = async (url, options = {}) => {
        calls.push({url, options}); return options.method === 'POST' ? mutation.promise : read.promise;
    };
    const save = page.fixWPConfig(); await tick();
    assert.equal(buttonExpression(html, 'fixWPConfig()', 'x-text', page), 'website.processing');
    assert.equal(buttonExpression(html, 'clearDatabase()', 'x-text', page), 'website.clear_database');
    assert.equal(buttonExpression(html, 'changeDBPassword()', 'x-text', page), 'website.confirm_change');
    assert.equal(buttonExpression(html, 'clearDatabase()', ':disabled', page), true, 'DB mutation lock remains shared');
    await page.changeDBPassword(); await page.clearDatabase();
    assert.equal(calls.length, 1);
    page.editTablePrefix = 'typed_during_save_'; mutation.resolve(ok({})); await tick();
    assert.equal(page.loading, false); assert.equal(page.backupsLoading, false); assert.equal(page.adminerLoading, false);
    read.resolve(ok({id: 1, table_prefix: 'wp_'})); await save;
    assert.equal(page.editTablePrefix, 'typed_during_save_');
    assert.deepEqual(calls.map(call => call.url), ['/websites/1/fix-wp-config', '/websites/1']);
    assert.equal(page.dbAction, ''); assert.equal(page.dbSubmitting, false);
});

test('prefix detection preserves manual typing while the real detection request is pending', async () => {
    const {page, context} = setup('database_detail.html', 'databaseDetail');
    page.site = {id: 1}; page.editTablePrefix = 'wp_'; const request = deferred(); let count = 0;
    const notices = []; context.t = (key, values) => key + ':' + values?.prefix;
    context.showToast = message => notices.push(message);
    context.api = async url => { assert.equal(url, '/websites/1/detect-table-prefix'); count++; return request.promise; };
    const read = page.detectTablePrefix(); page.editTablePrefix = 'manual_'; await page.detectTablePrefix();
    request.resolve(ok({prefix: 'detected_', candidates: ['detected_']})); await read;
    assert.equal(page.editTablePrefix, 'manual_'); assert.equal(count, 1);
    assert.equal(notices[0], 'website.detect_prefix_found:detected_');
});

test('Adminer activation keeps a later password draft and does not animate its stop button', async () => {
    const {page, context, html} = setup('database_detail.html', 'databaseDetail');
    page.site = {id: 1}; page.adminerStatusKnown = true; page.adminerPassword = 'submitted';
    const request = deferred(); const calls = [];
    context.api = async (url, options) => { calls.push({url, options}); return request.promise; };
    const save = page.enableAdminer(); page.adminerPassword = 'new draft'; await page.disableAdminer();
    assert.equal(buttonExpression(html, 'enableAdminer()', 'x-text', page), 'database.adminer_starting');
    assert.equal(buttonExpression(html, 'disableAdminer()', 'x-text', page), 'database.adminer_disable');
    assert.equal(calls.length, 1); assert.equal(calls[0].options.body.password, 'submitted');
    request.resolve(ok({enabled: true})); await save;
    assert.equal(page.adminerPassword, 'new draft'); assert.equal(page.adminerAction, '');
});

test('database password success does not close or clear an edited or reopened password form', async () => {
    for (const reopen of [false, true]) {
        const {page, context} = setup('database_detail.html', 'databaseDetail');
        page.site = {id: 1}; page.dbPasswordModal = true; page.newDBPassword = 'submitted';
        const request = deferred(); context.api = async () => request.promise;
        const save = page.changeDBPassword();
        if (reopen) page.dbPasswordVersion++; else page.newDBPassword = 'next password';
        request.resolve(ok({})); await save;
        assert.equal(page.dbPasswordModal, true);
        assert.equal(page.newDBPassword, reopen ? 'submitted' : 'next password');
    }
});

test('database URL save preserves edits made in the same modal during the request', async () => {
    const {page, context} = setup('database_detail.html', 'databaseDetail');
    page.site = {id: 1, domain: 'old.test'}; page.siteURLModal = true;
    page.newSiteURL = 'https://submitted.test'; const request = deferred(); const calls = [];
    context.api = async (url, options) => { calls.push({url, options}); return request.promise; };
    const save = page.updateSiteURLs(); await tick(); page.newSiteURL = 'https://draft.test';
    await page.updateSiteURLs(); assert.equal(calls.length, 1);
    request.resolve(ok({})); await save;
    assert.equal(page.siteURLModal, true); assert.equal(page.newSiteURL, 'https://draft.test');
    assert.equal(page.currentSiteURL, 'https://submitted.test');
});

test('old administrator reads cannot replace a reopened administrator form', async () => {
    const {page, context} = setup('database_detail.html', 'databaseDetail'); page.site = {id: 1};
    const first = deferred(), second = deferred(); let count = 0;
    context.api = async () => ++count === 1 ? first.promise : second.promise;
    const oldRead = page.openAdminModal(), newRead = page.openAdminModal();
    second.resolve(ok({administrators: [{id: 2, login: 'latest', email: 'new@test', display_name: 'New'}]})); await newRead;
    page.adminForm.displayName = 'unsaved name';
    first.resolve(ok({administrators: [{id: 1, login: 'stale'}]})); await oldRead;
    assert.equal(page.selectedAdminID, 2); assert.equal(page.adminForm.displayName, 'unsaved name');
});

test('administrator save retains a changed draft while updating only backup inventory', async () => {
    const {page, context} = setup('database_detail.html', 'databaseDetail'); page.site = {id: 1};
    page.adminModal = true; page.selectedAdminID = 3;
    Object.assign(page.adminForm, {login: 'admin', email: 'admin@test', displayName: 'Submitted'});
    const request = deferred(), calls = [];
    context.api = async (url, options = {}) => { calls.push({url, options}); return options.method ? request.promise : ok([]); };
    const save = page.updateAdministrator(); await tick(); page.adminForm.displayName = 'New draft';
    request.resolve(ok({administrator: {id: 3, display_name: 'Submitted'}})); await save;
    assert.equal(page.adminModal, true); assert.equal(page.adminForm.displayName, 'New draft');
    assert.deepEqual(calls.map(call => call.url), ['/websites/1/wp-administrators', '/websites/1/backups']);
});

test('closing and reopening backup policy discards an old read without overwriting the new draft', async () => {
    const {page, context} = setup('backups.html', 'backupsOverview');
    const first = deferred(), second = deferred(); let count = 0;
    context.api = async url => { assert.equal(url, '/backups/policy'); return ++count === 1 ? first.promise : second.promise; };
    const oldRead = page.openPolicy(); page.closePolicy(); const newRead = page.openPolicy();
    second.resolve(ok({sites: [{site_id: 2, db_keep_count: 7}]})); await newRead;
    page.policySites[0].db_keep_count = 12;
    first.resolve(ok({sites: [{site_id: 1, db_keep_count: 3}]})); await oldRead;
    assert.equal(page.policySites[0].site_id, 2); assert.equal(page.policySites[0].db_keep_count, 12);
    assert.equal(page.policyOpen, true); assert.equal(page.policyLoading, false);
});

test('backup policy save retains in-flight edits and sends a single reviewed policy snapshot', async () => {
    const {page, context} = setup('backups.html', 'backupsOverview');
    page.policyOpen = true;
    page.policySites = [{site_id: 1, db_enabled: true, db_keep_count: 7, incremental: {}, full: {}}];
    const request = deferred(), calls = [];
    context.api = async (url, options = {}) => {
        calls.push({url, options}); return options.method ? request.promise : ok({sites: [], panel_db_backups: []});
    };
    const save = page.savePolicy(); page.policySites[0].db_keep_count = 12;
    await page.savePolicy(); assert.equal(calls.length, 1); assert.equal(calls[0].options.body.sites[0].db_keep_count, 7);
    request.resolve(ok({})); await save;
    assert.equal(page.policyOpen, true); assert.equal(page.policySites[0].db_keep_count, 12);
    assert.equal(page.policySaving, false);
});

test('cron editing preserves keystrokes made in the same form during save', async () => {
    const {page, context} = setup('cron.html', 'cronManager');
    page.openEdit({id: 7, name: 'submitted', cron_expression: '0 2 * * *'});
    const request = deferred(), calls = [];
    context.api = async (url, options = {}) => { calls.push({url, options}); return options.method ? request.promise : ok([]); };
    const save = page.saveJob(); page.form.name = 'new draft'; await page.saveJob();
    request.resolve(ok({})); await save;
    assert.equal(page.showModal, true); assert.equal(page.form.name, 'new draft'); assert.equal(page.editingId, 7);
    assert.equal(calls.filter(call => call.options.method).length, 1);
    assert.equal(calls[0].options.body.name, 'submitted');
});

test('new cron submissions lock only their input form and success closes it without retaining a duplicate create draft', async () => {
    for (const succeeds of [true, false]) {
        const {page, context, html} = setup('cron.html', 'cronManager');
        const fields = html.match(/<form @submit\.prevent="saveJob">\s*<fieldset :disabled="([^"]+)"[^>]*>([\s\S]*?)<\/fieldset>/);
        assert(fields, 'submitted cron inputs must be grouped by a local fieldset lock');
        const models = [...html.matchAll(/x-model(?:\.number)?="(form\.[^"]+)"/g)].map(match => match[1]);
        for (const model of models) assert(fields[2].includes(`="${model}"`), `unlocked field: ${model}`);
        page.openCreate(); Object.assign(page.form, {name: 'new task', cron_expression: '0 2 * * *', command: 'true'});
        const request = deferred(), calls = [];
        context.api = async (url, options = {}) => { calls.push({url, options}); return options.method ? request.promise : ok([]); };
        const save = page.saveJob();
        assert.equal(vm.runInNewContext(fields[1], page), true, 'browser cannot type into a pending create form');
        await page.saveJob(); assert.equal(calls.length, 1);
        if (succeeds) request.resolve(ok({message: 'created'})); else request.reject(Error('not created'));
        await save;
        assert.equal(vm.runInNewContext(fields[1], page), false);
        assert.equal(page.editingId, null, 'the real create response does not provide an id');
        assert.equal(page.showModal, !succeeds);
        assert.equal(page.form.name, succeeds ? '' : 'new task');
        assert.equal(calls.filter(call => call.options.method === 'POST').length, 1);
    }
});

test('backup task rebuild authorization is consumed once without losing newer policy values', async () => {
    for (const succeeds of [true, false]) {
        const {page, context, html} = setup('backups.html', 'backupsOverview');
        page.policyOpen = true;
        page.policySites = [{site_id: 1, db_enabled: true, db_keep_count: 7, incremental: {rebuild: true}, full: {rebuild: true}}];
        for (const mode of ['incremental', 'full']) assert(html.includes(`x-model="site.${mode}.rebuild" :disabled="policySaving"`));
        const request = deferred(), writes = [];
        context.api = async (url, options = {}) => {
            if (options.method) { writes.push(options.body); return writes.length === 1 ? request.promise : ok({}); }
            return ok({sites: [], panel_db_backups: []});
        };
        const save = page.savePolicy(); await tick();
        assert.equal(page.policySaving, true); page.policySites[0].db_keep_count = 12;
        if (succeeds) request.resolve(ok({})); else request.reject(Error('not saved'));
        await save;
        assert.equal(page.policyOpen, true); assert.equal(page.policySites[0].db_keep_count, 12);
        assert.equal(page.policySites[0].incremental.rebuild, !succeeds);
        assert.equal(page.policySites[0].full.rebuild, !succeeds);
        assert.equal(page.policySaving, false);
        if (succeeds) {
            await page.savePolicy();
            assert.equal(writes[1].sites[0].incremental_rebuild, false);
            assert.equal(writes[1].sites[0].full_rebuild, false);
            assert.equal(writes[1].sites[0].db_keep_count, 12);
        }
    }
});

test('file mkdir retains a new directory draft and duplicate Enter does not repeat the mutation', async () => {
    const {page, context} = setup('files.html', 'fileManager');
    page.selectedSite = '1'; page.currentPath = '/'; page.showMkdir = true; page.mkdirName = 'submitted';
    const request = deferred(), calls = [];
    context.api = async (url, options = {}) => { calls.push({url, options}); return options.method ? request.promise : ok({files: []}); };
    const save = page.createDir(); page.mkdirName = 'next directory'; await page.createDir();
    request.resolve(ok({})); await save; await tick();
    assert.equal(page.showMkdir, true); assert.equal(page.mkdirName, 'next directory');
    assert.equal(page.mkdirSubmitting, false); assert.equal(calls.filter(call => call.options.method).length, 1);
    assert.equal(calls[0].options.body.name, 'submitted');
});

test('file rename preserves a later edit and advances its target to the successful filename', async () => {
    const {page, context} = setup('files.html', 'fileManager');
    page.selectedSite = '1'; page.currentPath = '/'; page.startRename('old.txt'); page.renameName = 'saved.txt';
    const request = deferred(), calls = [];
    context.api = async (url, options = {}) => { calls.push({url, options}); return options.method ? request.promise : ok({files: []}); };
    const save = page.doRename(); page.renameName = 'next.txt'; await page.doRename();
    request.resolve(ok({})); await save; await tick();
    assert.equal(page.showRename, true); assert.equal(page.renameName, 'next.txt'); assert.equal(page.renameTarget, 'saved.txt');
    assert.equal(calls.filter(call => call.options.method).length, 1); assert.equal(calls[0].options.body.old_path, '/old.txt');
});

test('a completed file rename never closes a newer rename editor', async () => {
    const {page, context} = setup('files.html', 'fileManager');
    page.selectedSite = '1'; page.currentPath = '/'; page.startRename('old.txt'); page.renameName = 'saved.txt';
    const request = deferred(); context.api = async (url, options = {}) => options.method ? request.promise : ok({files: []});
    const save = page.doRename(); page.startRename('another.txt'); page.renameName = 'another-draft.txt';
    request.resolve(ok({})); await save; await tick();
    assert.equal(page.showRename, true); assert.equal(page.renameTarget, 'another.txt'); assert.equal(page.renameName, 'another-draft.txt');
});

test('file security refresh labels only its requested operation while retaining the shared scan lock', async () => {
    const {page, context} = setup('firewall_controller.html', 'firewallManager');
    const html = fs.readFileSync(path.join(__dirname, '../../web/templates/firewall.html'), 'utf8');
    const request = deferred(), calls = [];
    context.api = async (url, options) => { calls.push({url, options}); return request.promise; };
    const refresh = page.refreshFileSecurityEvents(false);
    assert.equal(buttonExpression(html, 'refreshFileSecurityEvents(false)', 'x-text', page), 'firewall.refreshing');
    assert.equal(buttonExpression(html, 'refreshFileSecurityEvents(true)', 'x-text', page), 'firewall.clear_rescan');
    await page.refreshFileSecurityEvents(true); await page.loadFileSecurityEvents(); assert.equal(calls.length, 1);
    request.resolve(ok({events: []})); await refresh; assert.equal(page.fileSecurityAction, '');
});

test('manual ban preserves the next IP draft and does not repeat the first ban', async () => {
    const {page, context} = setup('firewall_controller.html', 'firewallManager');
    page.banIP = '192.0.2.1'; const request = deferred(), calls = [];
    context.api = async (url, options = {}) => { calls.push({url, options}); return options.method ? request.promise : ok({data: []}); };
    const save = page.manualBan(); page.banIP = '192.0.2.2'; await page.manualBan();
    request.resolve(ok({})); await save;
    assert.equal(page.banIP, '192.0.2.2'); assert.equal(calls.filter(call => call.options.method).length, 1);
    assert.equal(calls[0].options.body.ip, '192.0.2.1');
});

test('read-only SSH refresh cannot look like applying a port or send a concurrent mutation', async () => {
    const {page, context, html} = setup('ssh_port.html', 'sshPortManager');
    page.status = {available: true, pending: false, port: 22}; page.port = 2222; page.cloudReady = true;
    const request = deferred(), calls = [];
    context.api = async (url, options) => { calls.push({url, options}); return request.promise; };
    const refresh = page.refresh();
    assert.equal(buttonExpression(html, 'begin()', 'x-text', page), 'ssh_port.apply');
    assert.equal(buttonExpression(html, 'begin()', ':disabled', page), true);
    await page.begin(); assert.equal(calls.length, 1); assert.equal(calls[0].options.method, undefined);
    request.resolve(ok({port: 22, available: true, pending: false})); await refresh;
    assert.equal(page.port, 2222); assert.equal(page.cloudReady, true);
});

test('software health-only refresh does not animate the separate refresh-all action', async () => {
    const {page, context, html} = setup('software.html', 'softwareManager');
    const request = deferred(); context.api = async () => request.promise;
    const refresh = page.fetchHealth(true);
    assert.equal(page.healthLoading, true);
    assert.equal(buttonExpression(html, 'refreshAll()', 'x-text', page), 'common.refresh');
    request.resolve(ok({})); await refresh;
    assert.equal(page.refreshingAll, false);
});
