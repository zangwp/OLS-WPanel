const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const {test} = require('node:test');

function setup(file = 'database_detail.html', factory = 'databaseDetail') {
    const html = fs.readFileSync(path.join(__dirname, '../../web/templates', file), 'utf8');
    const source = [...html.matchAll(/<script[^>]*>([\s\S]*?)<\/script>/g)].map(match => match[1]).join('\n');
    const calls = [], notices = [];
    const context = {
        t: (key, values) => key + (values?.error ? ': ' + values.error : ''),
        currentLocale: () => 'en-US', showToast: (...args) => notices.push(args),
        window: {location: {pathname: '/panel/databases/1'}},
        api: async (url, options) => { calls.push({url, options}); throw Error('offline'); },
    };
    vm.createContext(context); vm.runInContext(source, context);
    return {page: context[factory](), context, html, calls, notices};
}

test('database detail load failure stays visible and retry loads independent sections', async () => {
    const {page, context, html} = setup();
    await page.fetchDetail();
    assert.equal(page.loading, false);
    assert.equal(page.site, null);
    assert.match(page.loadError, /offline/);
    assert.match(html, /x-show="loadError"[^>]*role="alert"/);
    assert.match(html, /@click="fetchDetail\(\)"/);
    context.api = async url => {
        if (url.endsWith('/backups')) throw Error('backup list unavailable');
        if (url.endsWith('/backups/settings')) return {success: true, data: {enabled: true, keep_count: 7}};
        if (url.endsWith('/adminer/status')) return {success: true, data: {enabled: true, domain: 'example.com'}};
        return {success: true, data: {id: 1}};
    };
    await page.fetchDetail();
    assert.equal(page.loadError, '');
    assert.equal(page.site.id, 1);
    assert.match(page.backupsError, /backup list unavailable/);
    assert.equal(page.backupSettingsLoaded, true);
    assert.equal(page.adminerStatusKnown, true);
});

test('failed or malformed Adminer status never declares an open database tool disabled', async () => {
    const {page, context, calls, html} = setup(); page.site = {id: 1};
    page.adminerStatus = {enabled: true, domain: 'example.com'};
    page.adminerStatusKnown = true;
    await page.fetchAdminerStatus();
    assert.equal(page.adminerStatus.enabled, true);
    assert.equal(page.adminerStatusKnown, false);
    assert.match(page.adminerError, /offline/);
    await page.enableAdminer();
    assert.equal(calls.length, 1, 'unknown state must not start or renew a database session');
    context.api = async () => ({success: true, data: {}});
    await page.fetchAdminerStatus();
    assert.equal(page.adminerStatusKnown, false);
    assert(page.adminerError);
    assert.match(html, /x-show="adminerStatus\.enabled \|\| !!adminerError"/);
});

test('Adminer can be explicitly closed while status is unknown and read failure is retryable', async () => {
    const {page, context} = setup(); page.site = {id: 1};
    await page.fetchAdminerStatus();
    const calls = [];
    context.api = async (url, options) => { calls.push({url, options}); return {success: true, data: {enabled: false}}; };
    await page.disableAdminer();
    assert.equal(calls[0].url, '/websites/1/adminer/disable');
    assert.equal(page.adminerStatusKnown, true);
    assert.equal(page.adminerStatus.enabled, false);
    assert.equal(page.adminerError, '');
    await page.fetchAdminerStatus();
    assert.equal(page.adminerStatusKnown, true);
});

test('Adminer read and mutation cannot overlap or fabricate success from incomplete responses', async () => {
    const {page, context, notices} = setup(); page.site = {id: 1};
    let resolve, calls = 0;
    context.api = async () => { calls++; return new Promise(done => { resolve = done; }); };
    const read = page.fetchAdminerStatus();
    await page.fetchAdminerStatus(); await page.enableAdminer(); await page.disableAdminer();
    assert.equal(calls, 1);
    resolve({success: true, data: {enabled: false}}); await read;
    const start = page.enableAdminer();
    await page.enableAdminer(); await page.fetchAdminerStatus();
    assert.equal(calls, 2);
    resolve({success: true, data: {}}); await start;
    assert.equal(page.adminerStatusKnown, false);
    assert(page.adminerError);
    assert.equal(notices.some(([, kind]) => kind === 'success'), false);
});

test('backup list read errors preserve prior rows and cannot appear as an empty list', async () => {
    const {page, context, html} = setup(); page.site = {id: 1};
    page.backups = [{id: 7, filename: 'backup.sql.gz'}];
    await page.fetchBackups();
    assert.equal(page.backups[0].id, 7);
    assert.match(page.backupsError, /offline/);
    assert.equal(page.backupsLoading, false);
    assert.match(html, /x-show="!backupsLoading && !backupsError && backups\.length === 0"/);
    context.api = async () => ({success: true, data: []}); await page.fetchBackups();
    assert.equal(page.backups.length, 0);
    assert.equal(page.backupsError, '');
});

test('database list distinguishes failed loads from an empty inventory and supports retry', async () => {
    const {page, context, html} = setup('databases.html', 'databaseManager');
    await page.loadDatabases();
    assert.match(page.loadError, /offline/);
    assert.match(html, /x-show="!loading && !loadError && filteredDatabases\(\)\.length === 0"/);
    context.api = async () => ({success: true, data: {}}); await page.loadDatabases();
    assert(page.loadError);
    context.api = async () => ({success: true, data: [{site_id: 1, db_name: 'example'}]}); await page.loadDatabases();
    assert.equal(page.loadError, '');
    assert.equal(page.databases[0].db_name, 'example');
});

test('database detail treats SQLite backup timestamps as UTC, matching its inventory', () => {
    const {page} = setup();
    assert.equal(page.formatDateTime('2026-10-13 01:02:03'), page.formatDateTime('2026-10-13T01:02:03Z'));
    assert.equal(page.formatDateTime(''), '');
    assert.equal(page.formatDateTime('invalid'), 'invalid');
});
