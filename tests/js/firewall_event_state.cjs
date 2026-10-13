const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const { test } = require('node:test');
const template = fs.readFileSync(path.join(__dirname, '../../web/templates/firewall.html'), 'utf8');
const script = fs.readFileSync(path.join(__dirname, '../../web/templates/firewall_controller.html'), 'utf8').match(/<script>([\s\S]*?)<\/script>/)[1];
const ok = data => ({ success: true, data });
const deferred = () => {
    let resolve, reject;
    const promise = new Promise((a, b) => { resolve = a; reject = b; });
    return { promise, resolve, reject };
};
function setup(api, confirmModal = async () => true) {
    const context = { api, confirmModal, t: key => key };
    vm.createContext(context);
    vm.runInContext(script, context);
    return context.firewallManager();
}

for (const [tab, method, prefix, rowsKey, responseKey] of [
    ['current', 'fetchBans', 'bans', 'bans', 'data'],
    ['history', 'fetchHistory', 'history', 'history', 'data'],
    ['wp', 'fetchWPSecurityReport', 'securityReport', 'securityReportItems', 'items'],
    ['files', 'loadFileSecurityEvents', 'fileSecurity', 'fileSecurityEvents', 'events'],
]) {
    test(`${tab} read failures never claim an empty successful security result`, async () => {
        let fail = true, malformed = false;
        const page = setup(async () => {
            if (fail) throw Error('offline');
            return ok(malformed ? {} : { [responseKey]: [] });
        });
        page.activeTab = tab;
        await page[method]();
        assert.equal(page[prefix + 'Loaded'], false);
        assert.equal(page.eventReadError(), 'offline');
        assert.equal(page.eventReadLoading(), false);
        fail = false; malformed = true;
        await page.retryEventRead();
        assert.equal(page[prefix + 'Loaded'], false);
        assert.equal(page.eventReadError(), 'followup.load_failed');
        malformed = false;
        await page.retryEventRead();
        assert.equal(page[prefix + 'Loaded'], true);
        assert.equal(page.eventReadError(), '');
        page[rowsKey] = [{ id: 7 }]; fail = true;
        await page[method]();
        assert.equal(page[rowsKey][0].id, 7);
        assert.equal(page.eventReadError(), 'offline');
        assert(template.includes(`!${prefix}Loading && !${prefix}Error`));
    });
}

for (const [method, prefix, rowsKey] of [['fetchBans', 'bans', 'bans'], ['fetchHistory', 'history', 'history']]) {
    test(`${method} rejects late results after a new search`, async () => {
        const first = deferred(), second = deferred();
        let calls = 0;
        const page = setup(() => ++calls === 1 ? first.promise : second.promise);
        const old = page[method](), latest = page[method]();
        second.resolve(ok({ data: [{ id: 2 }] }));
        await latest;
        first.reject(Error('old search failed'));
        await old;
        assert.equal(page[rowsKey][0].id, 2);
        assert.equal(page[prefix + 'Error'], '');
        assert.equal(page[prefix + 'Loading'], false);
    });
}

test('file rescan owns its confirmation lock and cannot overlap a background read', async () => {
    const confirmation = deferred();
    const calls = [];
    const page = setup(async (url, options) => { calls.push({ url, options }); return ok({ events: [] }); }, () => confirmation.promise);
    const refreshing = page.refreshFileSecurityEvents(true);
    await page.refreshFileSecurityEvents(true);
    await page.loadFileSecurityEvents();
    assert.equal(calls.length, 0);
    confirmation.resolve(true);
    await refreshing;
    assert.equal(calls.length, 1);
    assert.equal(calls[0].url, '/firewall/file-security-events/refresh?clear=1');
    assert.equal(page.fileSecurityLoading, false);
    assert.equal(page.fileSecurityLoaded, true);
});

test('current-tab deep links start a read and block a false empty state before completion', async () => {
    const pending = deferred();
    let reads = 0;
    const page = setup(() => { reads++; return pending.promise; });
    page.loadTab('current');
    page.loadTab('current');
    assert.equal(reads, 1);
    assert.equal(page.bansLoaded, false);
    assert.equal(page.bansLoading, true);
    pending.resolve(ok({ data: [] }));
    await new Promise(resolve => setImmediate(resolve));
    assert.equal(page.bansLoaded, true);
});

test('partial enforcement warnings appear with current bans and suppress a confirmed-empty claim', () => {
    const page = setup(async () => ok({ data: [] }));
    page.currentBanReadStatus = { nftables: false };
    assert.equal(page.hasCurrentBanReadWarning(), true);
    assert.match(template, /!hasCurrentBanReadWarning\(\) && bans.length === 0/);
    const warning = template.indexOf('x-show="hasCurrentBanReadWarning()"');
    const currentList = template.indexOf('<h3 class="text-lg font-semibold text-white">{{t .Lang "firewall.current_bans"}}</h3>');
    assert(warning > currentList, 'enforcement warning must stay with the current-ban list, not the WordPress report');
});
