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
const verification = (extra = {}) => ({ state: 'effective', checked_at: '2026-10-18T10:00:00Z', reason_code: 'tls_verified', source: 'loopback_tls', status: 'unchanged', ...extra });

function setup() {
    const calls = [], navigation = [];
    const context = { t: key => key, currentLocale: () => 'en-US', window: { location: { assign: url => navigation.push(url) } }, document: { getElementById: id => ({ scrollIntoView: () => navigation.push(id) }) }, api: async (url, options) => { calls.push({ url, options }); return response([]); } };
    vm.createContext(context); vm.runInContext(script, context);
    const page = Object.assign(context.siteSecuritySummary(), { site: { id: 1, status: 'active', site_type: 'wordpress' }, securityStatus: { checks: [check('configured')] }, securityStatusLoading: false, securityStatusGeneration: 0, siteSecurityTitle: key => key, setDetailTab: tab => navigation.push(tab), selectLogType: type => navigation.push(type), openSiteSSLSettings: () => navigation.push('ssl'), scrollDetailAnchor: () => navigation.push(context.window.location.hash), $nextTick: callback => callback() });
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

test('non-verifiable configuration uses a neutral state and never asks for a nonexistent verification', async () => {
    const {page,calls,context}=setup();
    page.securityStatus.checks=[check('configured',{key:'backup',can_verify:false,reason_code:'configured_not_run'})];
    assert.equal(page.summaryStateText('backup'),'site_security.state_configured');
    assert.equal(page.summaryStateClass('backup'),'badge-info');
    context.t=key=>key==='site_security.reason_configuration_saved' ? 'Saved configuration; view records' : key;
    assert.equal(page.summaryReason('backup'),'Saved configuration; view records');
    await page.verifySummaryCheck('backup');assert.equal(calls.length,0);
    page.securityStatus.checks=[check('configured',{key:'anomaly_monitor',can_verify:false,reason_code:'anomaly_check_stale'})];
    assert.equal(page.summaryStateText('anomaly_monitor'),'site_security.state_waiting_check');
});

test('file protection coverage and completed samples remain distinct from verified request protection',()=>{
    const {page}=setup();
    for(const [key,reason] of [['file_editing','file_editing_managed_by_file_lock'],['file_lock','file_lock_applied'],['uptime_monitor','uptime_check_succeeded'],['anomaly_monitor','anomaly_check_succeeded']]){
        page.securityStatus.checks=[check('ready',{key,reason_code:reason,runtime_ready:true,can_verify:false})];
        assert.equal(page.summaryStateText(key),'site_security.state_'+reason);
        assert.equal(page.summaryStateClass(key),'badge-info');
        page.securityStatus.checks[0].runtime_ready=false;
        assert.equal(page.summaryCheck(key).state,'unknown');
    }
});

test('maintenance and unknown operation evidence use translated explanations instead of a verification prompt',()=>{
    const {page,context}=setup();
    for (const locale of ['zh-CN','en-US']) {
        const messages=JSON.parse(fs.readFileSync(path.join(__dirname,'../../internal/i18n/locales/'+locale+'.json'),'utf8'));
        context.t=key=>key.split('.').reduce((value,part)=>value?.[part],messages)||key;
        for (const [key,state,reason] of [['file_lock','configured','file_lock_temporarily_unlocked'],['file_lock','unknown','file_lock_state_unknown'],['anomaly_monitor','unknown','anomaly_state_unknown']]) {
            page.securityStatus.checks=[check(state,{key,reason_code:reason,can_verify:false})];
            assert.equal(page.summaryReason(key),messages.site_security['reason_'+reason]);
            assert.notEqual(page.summaryReason(key),messages.site_security.reason_not_checked);
            assert(!page.summaryReason(key).includes('site_security.'));
            if (state==='configured') assert.equal(page.summaryStateText(key),messages.site_security.state_file_lock_temporarily_unlocked);
        }
    }
});

test('monitoring and protection actions lead to the real result or settings area without issuing verification',()=>{
    const {page,navigation,calls}=setup();
    for(const [key,target] of [['uptime_monitor','/panel/alert'],['backup','/panel/backups'],['anomaly_monitor','#site-wp-anomaly'],['file_lock','#site-protection'],['file_editing','#site-file-editing-control']]){
        page.securityStatus.checks=[check('configured',{key,can_verify:false})];page.openSummarySettings(key);
        assert.equal(navigation.pop(),target);
    }
    page.securityStatusLoading=true;page.verifyingKey='xmlrpc';page.openSummarySettings('uptime_monitor');assert.equal(navigation.pop(),'/panel/alert');
    page.securityStatusLoading=false;page.securityStatus.checks=[check('unsupported',{key:'anomaly_monitor',can_verify:false})];
    page.openSummarySettings('anomaly_monitor');assert.equal(navigation.length,0);assert.equal(calls.length,0);
});

test('a completed anomaly check refreshes the same website summary while failed checks do not publish new evidence',async()=>{
    const anomalyHTML=fs.readFileSync(path.join(__dirname,'../../web/templates/wp_anomaly_panel.html'),'utf8');
    const anomalyScript=anomalyHTML.match(/{{define "wp_anomaly_script"}}\s*<script>([\s\S]*?)<\/script>/)[1];
    const events=[],context={t:key=>key,currentLocale:()=> 'en-US',showToast(){},api:async()=>({success:true,data:{enabled:true,threshold:5,last_success:1720000000}})};
    vm.createContext(context);vm.runInContext(anomalyScript,context);
    const monitor=context.wpAnomalyMonitor(1);monitor.$dispatch=(name,detail)=>events.push({name,siteID:detail.site_id});
    await monitor.load();assert.equal(events.length,0);
    await monitor.check();assert.deepEqual(events,[{name:'site-anomaly-updated',siteID:1}]);
    events.length=0;context.api=async()=>{throw Error('site_busy');};await monitor.check();
    assert.equal(events.length,0);assert.equal(monitor.error,'anomaly.site_busy');
});

test('a previous successful verification remains historical without replacing the current configuration state', () => {
    const { page } = setup();
    page.securityStatus.checks = [check('configured', { verification: verification() })];
    assert.equal(page.summaryStateText('https'), 'site_security.state_configured');
    assert.equal(page.summaryStateClass('https'), 'badge-info');
    assert.equal(page.summaryHistoryText('https'), 'site_security.history_passed');
    assert.equal(page.summaryVerification('https').checked_at, '2026-10-18T10:00:00Z');
    assert.equal(page.summaryHistoryVisible('https'), true);
    page.securityStatus = { checks: [check('configured', { verification: verification() })] };
    assert.equal(page.summaryHistoryText('https'), 'site_security.history_passed');
});

test('relevant changes request rechecking while unavailable comparisons retain the historical time', () => {
    const { page } = setup();
    for (const [status, label] of [['changed', 'history_configuration_changed'], ['unavailable', 'history_configuration_unavailable']]) {
        page.securityStatus.checks = [check('configured', { verification: verification({ status }) })];
        assert.equal(page.summaryHistoryText('https'), 'site_security.' + label);
        assert.equal(page.summaryVerification('https').checked_at, '2026-10-18T10:00:00Z');
        assert.equal(page.summaryStateClass('https'), 'badge-info');
        assert.equal(page.summaryHistoryResult('https'), 'site_security.history_passed');
    }
});

test('new current errors or disabled protection remain visible despite a previous successful verification', () => {
    const { page } = setup();
    for (const state of ['error', 'disabled', 'unknown']) {
        page.securityStatus.checks = [check(state, { configured: false, verification: verification() })];
        assert.equal(page.summaryStateText('https'), 'website.security_state_' + state);
        assert.notEqual(page.summaryStateClass('https'), 'badge-success');
        assert.equal(page.summaryHistoryText('https'), 'site_security.history_passed');
    }
    page.securityStatus.checks = [check('effective', { effective: true, verification: verification({ state: 'error' }) })];
    assert.equal(page.summaryStateClass('https'), 'badge-success');
    assert.equal(page.summaryHistoryText('https'), 'site_security.history_failed');
});

test('missing history does not imply disabled protection or demand manual checks for already observed requests', () => {
    const { page } = setup();
    assert.equal(page.summaryStateText('https'), 'site_security.state_configured');
    assert.equal(page.summaryStateClass('https'), 'badge-info');
    assert.equal(page.summaryHistoryText('https'), 'site_security.history_never_checked');
    assert.equal(page.summaryHistoryVisible('https'), true);
    page.securityStatus.verification_unavailable = true;
    assert.equal(page.summaryHistoryVisible('https'), false);
    page.securityStatus.verification_unavailable = false;
    for (const observation of [check('effective', { effective: true }), check('ready', { runtime_ready: true }), check('configured', { can_verify: false })]) {
        page.securityStatus.checks = [observation];
        assert.equal(page.summaryHistoryVisible('https'), false);
    }
});

test('invalid historical records cannot claim a previous successful verification', () => {
    const { page } = setup();
    for (const history of [null, verification({ checked_at: '' }), verification({ checked_at: 'invalid' }), verification({ status: 'invented' }), verification({ state: 'invented' })]) {
        page.securityStatus.checks = [check('configured', { verification: history })];
        assert.equal(page.summaryVerification('https'), null);
        assert.equal(page.summaryHistoryText('https'), 'site_security.history_never_checked');
    }
});

test('a successful response containing a failed check reports that failure instead of announcing a pass', async () => {
    const { page, context } = setup();
    context.api = async () => response([check('configured', { reason_code: 'tls_untrusted', verification: verification({ state: 'configured', reason_code: 'tls_untrusted' }) })]);
    await page.verifySummaryCheck('https');
    assert(page.verificationError.includes('site_security.verification_result_failed'));
    assert.equal(page.verificationMessage, '');
    assert.equal(page.summaryStateClass('https'), 'badge-warning');
    assert.equal(page.summaryHistoryText('https'), 'site_security.history_failed');
});

test('unavailable runtime checks report incomplete while readiness never claims tested request blocking', async () => {
    const { page, context } = setup();
    context.api = async () => response([check('configured', { reason_code: 'core_runtime_unavailable', verification: verification({ state: 'configured', reason_code: 'core_runtime_unavailable' }) })]);
    await page.verifySummaryCheck('https');
    assert(page.verificationError.includes('site_security.verification_result_incomplete'));
    assert.equal(page.summaryHistoryText('https'), 'site_security.history_incomplete');
    context.api = async () => response([check('ready', { runtime_ready: true, verification: verification({ state: 'ready', reason_code: 'service_ready' }) })]);
    await page.verifySummaryCheck('https');
    assert.equal(page.verificationError, '');
    assert(page.verificationMessage.includes('site_security.verification_result_ready'));
    assert.equal(page.summaryHistoryText('https'), 'site_security.history_ready');
    assert.equal(page.summaryStateClass('https'), 'badge-info');
});

test('saving failures explain that the check ran without claiming durable success', async () => {
    const { page, context } = setup();
    context.api = async () => { const error = new Error('server message'); error.code = 'verification_save_failed'; throw error; };
    const previous = page.securityStatus;
    await page.verifySummaryCheck('https');
    assert.equal(page.verificationError, 'site_security.verification_save_failed');
    assert.equal(page.verificationMessage, '');
    assert.equal(page.securityStatus, previous);
    context.api = async () => ({ success: false, error_code: 'verification_save_failed' });
    await page.verifySummaryCheck('https');
    assert.equal(page.verificationError, 'site_security.verification_save_failed');
});

test('only the clicked verification control changes its native disabled and loading appearance', () => {
    const control = html.match(/<button[^>]+@click="verifySummaryCheck\(key\)"[^>]*>/)[0];
    assert(control.includes(':disabled="securityStatusLoading || verifyingKey === key || site.status !== \'active\'"'));
    assert(control.includes(':aria-disabled="securityStatusLoading || !!verifyingKey || site.status !== \'active\'"'));
    assert(control.includes("verifyingKey === key ? t('site_security.verifying')"));
    assert(html.includes('aria-live="polite"'));
    assert(html.includes('securityStatus?.verification_unavailable'));
});

test('verification history and outcome labels exist in both supported languages', () => {
    const keys = ['verification_save_failed', 'verification_history_unavailable', 'last_verification', 'last_verification_evidence', 'verification_applicability', 'history_never_checked', 'history_passed', 'history_ready', 'history_failed', 'history_incomplete', 'history_configuration_changed', 'history_configuration_unavailable', 'verification_result_passed', 'verification_result_ready', 'verification_result_failed', 'verification_result_incomplete', 'recheck_short'];
    for (const locale of ['zh-CN', 'en-US']) {
        const messages = JSON.parse(fs.readFileSync(path.join(__dirname, '../../internal/i18n/locales/' + locale + '.json'), 'utf8'));
        for (const key of keys) assert.equal(typeof messages.site_security[key], 'string', locale + ': ' + key);
    }
});
