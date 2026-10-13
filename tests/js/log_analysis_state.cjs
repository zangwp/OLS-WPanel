const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const { test } = require('node:test');

const template = fs.readFileSync(path.join(__dirname, '../../web/templates/log_analysis.html'), 'utf8');
const script = template.match(/<script>([\s\S]*?)<\/script>/)[1].replace(/{{[\s\S]*?}}/g, 'translated');
const ok = data => ({ success: true, data });
const deferred = () => {
    let resolve, reject;
    const promise = new Promise((a, b) => { resolve = a; reject = b; });
    return { promise, resolve, reject };
};
function setup(api) {
    const context = { api, AbortController, clearTimeout, t: key => key };
    vm.createContext(context);
    vm.runInContext(script, context);
    return context.logAnalysisPage();
}

test('history distinguishes loading and failed reads from a successful empty result', async () => {
    const pending = deferred();
    let response = pending.promise;
    const page = setup(() => response);
    page.siteID = '1';
    const loading = page.loadHistory();
    assert.equal(page.historyLoading, true);
    assert.equal(page.historyLoaded, false);
    pending.reject(Error('offline'));
    await loading;
    assert.equal(page.historyLoading, false);
    assert.equal(page.historyLoaded, false);
    assert.equal(page.historyError, 'offline');
    response = Promise.resolve(ok([]));
    await page.loadHistory();
    assert.equal(page.historyLoaded, true);
    assert.equal(page.historyError, '');
    assert.match(template, /x-show="siteID && historyLoaded && !historyLoading && !historyError && history.length === 0"/);
});

test('invalid history responses preserve the prior list and allow retry', async () => {
    let result = ok([{ id: 7 }]);
    const page = setup(async () => result);
    page.siteID = '1';
    await page.loadHistory();
    for (const invalid of [{ success: false }, ok(null), ok({})]) {
        result = invalid;
        await page.loadHistory();
        assert.equal(page.history[0].id, 7);
        assert.equal(page.historyError, 'log_analysis.load_failed');
        assert.equal(page.historyLoading, false);
    }
    result = ok([{ id: 8 }]);
    await page.loadHistory();
    assert.equal(page.history[0].id, 8);
    assert.equal(page.historyError, '');
});

test('late history failures cannot overwrite a new site or its loading state', async () => {
    const old = deferred(), latest = deferred();
    const page = setup(url => url.endsWith('=1') ? old.promise : latest.promise);
    page.siteID = '1';
    const first = page.loadHistory();
    page.siteID = '2';
    const second = page.onSiteChange();
    old.reject(Error('old site failed'));
    await first;
    assert.equal(page.historyLoading, true);
    assert.equal(page.historyError, '');
    latest.resolve(ok([]));
    await second;
    assert.equal(page.historyLoading, false);
    assert.equal(page.historyLoaded, true);
});

test('destroy detaches pending history and releases its loading state', async () => {
    const pending = deferred();
    const page = setup(() => pending.promise);
    page.siteID = '1';
    const loading = page.loadHistory();
    page.destroy();
    pending.reject(Error('late failure'));
    await loading;
    assert.equal(page.historyLoading, false);
    assert.equal(page.historyError, '');
});

test('failed or absent analysis does not display a low-risk assessment', () => {
    const page = setup(async () => ok([]));
    for (const status of ['failed', 'running', 'pending', 'completed']) {
        page.job = { status };
        page.report = null;
        assert.equal(page.overallRisk(), null);
        assert.equal(page.overallRiskClass(), '');
        assert.equal(page.overallRiskText(), '');
    }
    page.job = { status: 'failed' };
    page.report = { findings: [] };
    assert.equal(page.overallRisk(), null);
    page.job.status = 'completed';
    assert.equal(page.overallRisk(), 'low');
    page.report.findings = [{ severity: 'medium' }];
    assert.equal(page.overallRisk(), 'medium');
    page.report.findings.push({ severity: 'high' });
    assert.equal(page.overallRisk(), 'high');
});
