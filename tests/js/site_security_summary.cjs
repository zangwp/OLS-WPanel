const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const { test } = require('node:test');

const html = fs.readFileSync(path.join(__dirname, '../../web/templates/site_security_summary.html'), 'utf8');
const script = html.match(/{{define "site_security_summary_script"}}\s*<script>([\s\S]*?)<\/script>/)[1].replaceAll('{{.RandomSuffix}}', 'panel');
const deferred = () => { let resolve, reject; const promise = new Promise((a, b) => { resolve = a; reject = b; }); return { promise, resolve, reject }; };
const check = (state, extra = {}) => ({ key: 'https', state, configured: true, can_verify: true, action: 'ssl', ...extra });
const response = checks => ({ success: true, data: { site_id: 1, checks } });

function setup() {
    const calls = [], navigation = [];
    const context = { t: key => key, currentLocale: () => 'en-US', window: { location: { assign: url => navigation.push(url) } }, document: { getElementById: id => ({ scrollIntoView: () => navigation.push(id) }) }, api: async (url, options) => { calls.push({ url, options }); return response([]); } };
    vm.createContext(context); vm.runInContext(script, context);
    const page = Object.assign(context.siteSecuritySummary(), { site: { id: 1, status: 'active', site_type: 'wordpress' }, securityStatus: { checks: [check('configured')] }, securityStatusLoading: false, securityStatusGeneration: 0, setDetailTab: tab => navigation.push(tab), selectLogType: type => navigation.push(type), openSiteSSLSettings: () => navigation.push('ssl'), $nextTick: callback => callback() });
    return { page, context, calls, navigation };
}

test('section and script definitions are separate so Alpine template cloning never controls script execution', () => {
    const section = html.slice(0, html.indexOf('{{define "site_security_summary_script"}}'));
    assert(!section.includes('<script>')); assert(section.includes('x-data="siteSecuritySummary()"'));
});

test('readiness and isolated core verification have distinct blue states; only verified requests are green', () => {
    const { page } = setup();
    for (const state of ['ready', 'runtime_verified']) { page.securityStatus.checks = [check(state, { runtime_ready: true, effective: null })]; assert.equal(page.summaryStateText('https'), 'site_security.state_' + state); assert.equal(page.summaryStateClass('https'), 'badge-info'); }
    page.securityStatus.checks = [check('effective', { effective: true })]; assert.equal(page.summaryStateClass('https'), 'badge-success');
    page.securityStatusLoading = true; assert.equal(page.summaryStateClass('https'), 'badge-info'); assert.equal(page.summaryStateText('https'), 'website.security_checking');
});

test('malformed or contradictory observations cannot claim readiness or verified protection', () => {
    const { page } = setup();
    for (const value of [null, check('invented'), check('effective', { effective: null }), check('effective', { effective: true, configured: false }), check('ready', { runtime_ready: false }), check('runtime_verified', { runtime_ready: true, configured: null })]) { page.securityStatus.checks = [value]; assert.equal(page.summaryCheck('https').state, 'unknown'); assert.notEqual(page.summaryStateClass('https'), 'badge-success'); }
});

test('verification sends one bounded same-site POST and updates canonical status only after valid JSON', async () => {
    const { page, context, calls } = setup(); const wait = deferred(); context.api = (url, options) => { calls.push({ url, options }); return wait.promise; };
    const pending = page.verifySummaryCheck('https'); await page.verifySummaryCheck('https'); assert.equal(calls.length, 1); assert.equal(calls[0].url, '/websites/1/security-verify'); assert.equal(calls[0].options.method, 'POST'); assert.equal(calls[0].options.body.key, 'https'); assert.equal(calls[0].options.cache, 'no-store'); assert.equal(calls[0].options.timeout, 20000);
    wait.resolve(response([check('effective', { effective: true })])); await pending; assert.equal(page.summaryStateClass('https'), 'badge-success'); assert.equal(page.verifyingKey, '');
});

test('failed or wrong-site verification does not replace previous evidence or invent success', async () => {
    const { page, context } = setup(); const previous = page.securityStatus;
    for (const value of [{ success: false, data: null }, { success: true, data: { site_id: 2, checks: [] } }, { success: true, data: { site_id: 1, checks: {} } }, null]) { context.api = async () => value; await page.verifySummaryCheck('https'); assert.equal(page.securityStatus, previous); assert(page.verificationError); assert.equal(page.verifyingKey, ''); }
    context.api = async () => { throw new Error('temporarily unavailable'); }; await page.verifySummaryCheck('https'); assert.equal(page.verificationError, 'temporarily unavailable'); assert.equal(page.summaryCheck('https').state, 'configured');
});

test('verification started before settings change or navigation cannot restore stale results', async () => {
    for (const changeSite of [false, true]) { const { page, context } = setup(); const wait = deferred(); context.api = () => wait.promise; const pending = page.verifySummaryCheck('https'); const previous = page.securityStatus; if (changeSite) page.site = { ...page.site, id: 2 }; else page.securityStatusGeneration++; wait.resolve(response([check('effective', { effective: true })])); await pending; assert.equal(page.securityStatus, previous); assert.equal(page.verificationError, ''); }
});

test('unavailable checks, loading and parallel verification never issue a request', async () => {
    const { page, calls } = setup(); page.securityStatusLoading = true; await page.verifySummaryCheck('https'); page.securityStatusLoading = false; page.securityStatus.checks[0].can_verify = false; await page.verifySummaryCheck('https'); page.site = null; await page.verifySummaryCheck('https'); assert.equal(calls.length, 0);
});

test('stopped sites cannot start a verification even if the previous observation allowed it', async () => {
    const { page, calls } = setup(); page.site.status = 'stopped';
    const previous = page.securityStatus;
    await page.verifySummaryCheck('https');
    assert.equal(calls.length, 0); assert.equal(page.verifyingKey, ''); assert.equal(page.securityStatus, previous);
});

test('log actions open the applicable site log without an unrelated settings navigation', () => {
    const { page, navigation } = setup();
    page.openSummaryLogs(); assert.deepEqual(navigation.splice(0), ['logs', 'security']); page.site.site_type = 'php'; page.openSummaryLogs(); assert.deepEqual(navigation.splice(0), ['logs', 'error']);
});
