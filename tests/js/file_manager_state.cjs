const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const { test } = require('node:test');

const source = fs.readFileSync(path.join(__dirname, '../../web/templates/files.html'), 'utf8')
    .match(/<script>([\s\S]*?)<\/script>/)[1];
const deferred = () => {
    let resolve, reject;
    const promise = new Promise((yes, no) => { resolve = yes; reject = no; });
    return { promise, resolve, reject };
};
const listing = (...names) => ({ success: true, data: { files: names.map(name => ({ name, is_dir: false })) } });

function setup(overrides = {}) {
    const context = {
        t: key => key, showToast() {}, confirmModal: async () => true,
        URL, URLSearchParams, FormData, Blob,
        window: { location: { href: 'https://panel.test/panel/files', search: '' }, history: { replaceState() {} } },
        document: { body: { dataset: { panelPrefix: '/panel' } }, querySelector: () => ({ content: 'csrf', value: '' }) },
        api: async () => listing(),
        ...overrides,
    };
    vm.createContext(context);
    vm.runInContext(source, context);
    const page = context.fileManager();
    page.selectedSite = '1';
    page.currentPath = '/old';
    page.files = [{ name: 'index.php', is_dir: false }];
    return { context, page };
}

test('pending/failed navigation never applies old file actions to a new directory', async () => {
    const request = deferred(), calls = [];
    const { page } = setup({ api: (url, options) => { calls.push({ url, options }); return request.promise; } });
    const navigation = page.enterDir('child');
    assert.equal(page.currentPath, '/old');
    assert.equal(page.visibleFiles.length, 0);
    assert.equal(page.loadingFiles, true);
    await page.deleteItems(['index.php']);
    assert.equal(calls.filter(call => call.options?.method === 'DELETE').length, 0);
    request.reject(new Error('offline'));
    await navigation;
    assert.equal(page.currentPath, '/old');
    assert.equal(page.visibleFiles[0].name, 'index.php');
    assert.equal(page.loadError, 'offline');
    assert.equal(page.loadingFiles, false);
});

test('only the latest listing commits its site/path/rows; old failures cannot replace state', async () => {
    const first = deferred(), second = deferred();
    let count = 0;
    const { page } = setup({ api: () => (++count === 1 ? first.promise : second.promise) });
    page.selected = ['index.php'];
    const oldNavigation = page.openRoot(2);
    const latestNavigation = page.loadFiles({ siteID: '3', path: '/new', page: 1 });
    assert.equal(page.selectedSite, '1');
    second.resolve(listing('new.php'));
    await latestNavigation;
    assert.equal(page.selectedSite, '3');
    assert.equal(page.currentPath, '/new');
    assert.equal(page.visibleFiles[0].name, 'new.php');
    assert.equal(page.selected.length, 0);
    first.reject(new Error('old failure'));
    await oldNavigation;
    assert.equal(page.currentPath, '/new');
    assert.equal(page.loadError, '');
    assert.equal(page.loadingFiles, false);
});

test('leaving the directory invalidates a pending listing', async () => {
    const request = deferred();
    const { page } = setup({ api: () => request.promise });
    const navigation = page.enterDir('child');
    page.showRootList();
    request.resolve(listing('late.php'));
    await navigation;
    assert.equal(page.selectedSite, '');
    assert.equal(page.files.length, 0);
    assert.equal(page.loadingFiles, false);
});

test('batch deletion fixes names/site/path before confirmation and across requests', async () => {
    const confirmation = deferred(), firstDelete = deferred(), calls = [];
    const { page } = setup({
        confirmModal: () => confirmation.promise,
        api: (url, options) => {
            calls.push({ url, options });
            return calls.length === 1 ? firstDelete.promise : Promise.resolve({ success: true });
        },
    });
    const names = ['a.php', 'b.php'];
    const deletion = page.deleteItems(names);
    names.push('not-confirmed.php');
    page.selectedSite = '2';
    page.currentPath = '/different';
    confirmation.resolve(true);
    await Promise.resolve();
    firstDelete.resolve({ success: true });
    await deletion;
    assert.deepEqual(calls.map(call => call.url), [
        '/files/delete?site_id=1&path=%2Fold%2Fa.php',
        '/files/delete?site_id=1&path=%2Fold%2Fb.php',
    ]);
});

test('paste conflict retries preserve the confirmed destination', async () => {
    const calls = [];
    const { page, context } = setup();
    page.clipboard = { action: 'copy', site_id: '4', src_path: '/source', names: ['a.php'] };
    context.api = async (url, options) => {
        calls.push({ url, body: options.body });
        if (calls.length === 1) throw Object.assign(new Error('exists'), { conflicts: ['a.php'] });
        return { success: true };
    };
    context.confirmModal = async () => { page.selectedSite = '2'; page.currentPath = '/different'; return true; };
    await page.pasteItems();
    assert.equal(calls.length, 2);
    for (const call of calls) {
        assert.equal(call.body.dest_site_id, 1);
        assert.equal(call.body.dest_path, '/old');
    }
    assert.equal(calls[1].body.conflict_policy, 'overwrite');
});

test('extract confirmation and overwrite retry retain the original archive target', async () => {
    const calls = [];
    const { page, context } = setup();
    context.confirmModal = async () => { page.selectedSite = '2'; page.currentPath = '/different'; return true; };
    context.api = async (url) => {
        calls.push(url);
        if (calls.length === 1) throw Object.assign(new Error('exists'), { conflicts: ['a.php'] });
        return { success: true };
    };
    await page.decompressFile('archive.zip');
    assert.deepEqual(calls, [
        '/files/unzip?site_id=1&path=%2Fold%2Farchive.zip',
        '/files/unzip?site_id=1&path=%2Fold%2Farchive.zip&overwrite=1',
    ]);
});

test('chunk upload preserves its destination during confirmation and navigation', async () => {
    const requests = [];
    const { page, context } = setup();
    page.uploadTarget = { name: 'index.php', size: 3, lastModified: 0, slice: (start, end) => new Blob(['abc']).slice(start, end) };
    context.confirmModal = async () => { page.currentPath = '/after-confirm'; return true; };
    context.fetch = async (url, options) => {
        const body = typeof options.body === 'string' ? JSON.parse(options.body) : null;
        requests.push({ url, body });
        if (url.endsWith('/init')) return { json: async () => ({ success: true, data: { upload_id: 'upload', completed_chunks: [] } }) };
        if (url.endsWith('/chunk')) { page.selectedSite = '3'; page.currentPath = '/after-chunk'; }
        return { json: async () => ({ success: true }) };
    };
    await page.uploadFile();
    const init = requests.find(request => request.url.endsWith('/init')).body;
    const complete = requests.find(request => request.url.endsWith('/complete')).body;
    assert.equal(init.site_id, 1);
    assert.equal(init.path, '/old');
    assert.equal(complete.site_id, init.site_id);
    assert.equal(complete.path, init.path);
    assert.equal(page.uploading, false);
});
