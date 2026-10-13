const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const {test} = require('node:test');

function setup() {
    const html = fs.readFileSync(path.join(__dirname, '../../web/templates/website_new.html'), 'utf8');
    const source = html.match(/<script>([\s\S]*?)<\/script>/)[1];
    const calls = [];
    const context = {
        t: (key, values) => key + (values?.domain ? ': ' + values.domain : ''),
        setTimeout() {}, window: {}, document: {},
        api: async (url, options) => { calls.push({url, options}); return {success: true, data: {id: 1}}; },
    };
    vm.createContext(context); vm.runInContext(source, context);
    return {page: context.createWebsite(), context, calls};
}

test('database password generation uses browser cryptographic randomness for every character', () => {
    const {page, context} = setup();
    let bytes = 0;
    context.crypto = {getRandomValues(values) { bytes += values.byteLength; values.set(Array.from({length: 24}, (_, i) => i * 3)); return values; }};
    context.Math = {random() { throw Error('weak random generator used'); }};
    page.generatePassword();
    assert.equal(bytes, 96);
    assert.equal(page.dbPassword.length, 24);
    assert.match(page.dbPassword, /^[a-zA-Z0-9!@#$%^&*]{24}$/);
    assert.equal(new Set(page.dbPassword).size, 24);
});

test('repeated creation during SSL preflight sends one immutable site request', async () => {
    const {page, context, calls} = setup();
    let resolve;
    const pending = new Promise(done => { resolve = done; });
    context.api = async (url, options) => {
        calls.push({url, options});
        return url.endsWith('/ssl-preflight') ? pending : {success: true, data: {id: 1}};
    };
    page.domain = 'original.example'; page.sslEnabled = true;
    const creating = page.submit();
    page.domain = 'edited.example';
    await page.submit();
    assert.equal(calls.length, 1);
    resolve({success: true, data: {warnings: [], hard_warnings: []}}); await creating;
    assert.equal(calls.length, 2);
    assert.equal(calls[1].options.body.domain, 'original.example');
    assert.equal(calls[1].options.body.site_type, 'wordpress');
    assert.equal(calls[1].options.body.document_root_subdir, undefined);
    assert.equal(page.success, 'website.created: original.example');
    assert.equal(page.loading, false);
});

test('cancelled or failed creation releases its busy guard for an explicit retry', async () => {
    const {page, context} = setup(); page.domain = 'example.com';
    context.api = async () => { throw Error('offline'); };
    await page.submit();
    assert.equal(page.loading, false); assert.equal(page.error, 'offline');
    context.api = async () => ({success: true, data: {id: 2}});
    await page.submit();
    assert.equal(page.loading, false); assert.equal(page.error, ''); assert.equal(page.createdSiteID, 2);
});
