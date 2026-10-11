const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const { test } = require('node:test');

const html = fs.readFileSync(path.join(__dirname, '../../web/templates/site_cloudflare_security.html'), 'utf8');
const source = html.match(/<script>([\s\S]*?)<\/script>/)[1];
const locale = language => JSON.parse(fs.readFileSync(path.join(__dirname, `../../internal/i18n/locales/${language}.json`), 'utf8'));
const lookup = (messages, key) => key.split('.').reduce((value, part) => value?.[part], messages) || key;
const ok = data => ({ success: true, data });
const account = 'a'.repeat(32), zone = 'b'.repeat(32), rule = 'c'.repeat(32);
const config = (overrides = {}) => ({
    site_id: 2, hostname: 'shop.example.com', enabled: true, account_id: account,
    zone_id: zone, zone_name: 'example.com', token_configured: true, rule_id: rule,
    sync_status: 'synced', last_sync_at: '2026-10-11 08:00:00', last_error: '',
    scope: 'shared_web_bans', cleanup_required: true, active_ip_count: 0, active_ip_count_known: true,
    website_hostnames: ['shop.example.com'], covered_hostnames: ['shop.example.com'], coverage_error: '',
    ...overrides,
});
function setup(respond = async () => ok(config()), language = 'zh-CN') {
    const calls = [], messages = locale(language), t = key => lookup(messages, key);
    const context = {
        AbortController, currentLocale: () => language, t,
        api: async (url, options) => { calls.push({ url, options }); return respond(url, options); },
    };
    vm.createContext(context);
    vm.runInContext(source, context);
    const page = context.siteCloudflareSecurity();
    page.site = { id: 2, domain: 'shop.example.com' };
    const evaluate = expression => vm.runInNewContext(expression, {
        t, ...Object.fromEntries(Object.entries(page).map(([key, value]) => [key, typeof value === 'function' ? value.bind(page) : value])),
    });
    const expressions = [...html.matchAll(/\bx-text="([^"]*)"/g)].map(match => match[1]);
    const ruleText = () => evaluate(expressions.find(value => value.startsWith('cfConfig.rule_id')));
    const standbyShown = () => evaluate(html.match(/x-show="([^"]*cloudflareStatus\(\)[^"]*)"/)[1]);
    return { page, calls, t, context, ruleText, standbyShown };
}

test('unloaded Cloudflare state does not claim a rule or zero bans', () => {
    const { page, t, ruleText, standbyShown } = setup();
    assert.equal(page.cloudflareStatusLabel(), t('cloudflare_security.status_unknown'));
    assert.equal(page.cloudflareActiveIPCount(), t('cloudflare_security.active_ip_count_unknown'));
    assert.equal(ruleText(), t('cloudflare_security.rule_pending'));
    assert.equal(standbyShown(), false);
    assert.equal(page.canSyncCloudflare(), false);
});

for (const language of ['zh-CN', 'en-US']) {
    test(`${language}: verified empty rule is visible and sync notice reports standby`, async () => {
        const { page, calls, t, ruleText, standbyShown } = setup(undefined, language);
        assert.equal(await page.loadCloudflare(), true);
        assert.equal(page.cloudflareStatusLabel(), t('cloudflare_security.status_ready'));
        assert.equal(page.cloudflareActiveIPCount(), '0');
        assert.equal(ruleText(), rule);
        assert.equal(standbyShown(), true);
        assert.equal(await page.syncCloudflare(), true);
        assert.equal(page.cfNotice, t('cloudflare_security.status_ready'));
        assert.equal(calls[1].url, '/websites/2/cloudflare-security/sync');
        assert.equal(calls[1].options.method, 'POST');
        assert.equal(calls[1].options.cache, 'no-store');
    });
}

test('active bans and unknown counts retain a synced rule without claiming standby', async () => {
    for (const count of [1, 12, 0, 55]) {
        const known = count === 1 || count === 12;
        const { page, t, ruleText, standbyShown } = setup(async () => ok(config({ active_ip_count: count, active_ip_count_known: known })));
        await page.loadCloudflare();
        assert.equal(page.cfConfig.active_ip_count, count, 'API count is preserved, even when its availability is unknown');
        assert.equal(page.cfConfig.active_ip_count_known, known);
        assert.equal(page.cloudflareActiveIPCount(), known ? String(count) : t('cloudflare_security.active_ip_count_unknown'));
        assert.equal(page.cloudflareStatusLabel(), t('cloudflare_security.status_synced'));
        assert.equal(ruleText(), rule);
        assert.equal(standbyShown(), false);
        await page.syncCloudflare();
        assert.equal(page.cfNotice, t('cloudflare_security.status_synced'));
    }
});

test('legacy synced state without a rule requires creation, and pending updates never claim standby', async () => {
    for (const state of [config({ rule_id: '', cleanup_required: false }), config({ sync_status: 'pending' })]) {
        const { page, t, standbyShown } = setup(async () => ok(state));
        await page.loadCloudflare();
        const key = state.rule_id ? 'status_pending' : 'status_rule_missing';
        assert.equal(page.cloudflareStatusLabel(), t('cloudflare_security.' + key));
        assert.equal(page.cloudflareActiveIPCount(), '0');
        assert.equal(standbyShown(), false);
        await page.syncCloudflare();
        assert.equal(page.cfNotice, t('cloudflare_security.' + key), 'sync notices use returned state rather than blanket success');
    }
});

test('invalid counts and malformed rule IDs are rejected before replacing any confirmed configuration', () => {
    for (const overrides of [
        { active_ip_count: undefined }, { active_ip_count: '0' }, { active_ip_count: -1 },
        { active_ip_count: 0.5 }, { active_ip_count: NaN }, { active_ip_count: Infinity },
        { active_ip_count: Number.MAX_SAFE_INTEGER + 1 }, { active_ip_count_known: undefined },
        { active_ip_count_known: 'false' }, { active_ip_count_known: 0 }, { rule_id: 123 },
        { rule_id: 'not-a-rule-id' }, { rule_id: ' ' }, { rule_id: 'c'.repeat(31) },
        { rule_id: 'c'.repeat(33) }, { rule_id: 'z'.repeat(32) }, { rule_id: undefined },
    ]) {
        const { page, t } = setup();
        page.applyCloudflareConfig(config({ active_ip_count: 4 }), 2);
        const previous = page.cfConfig;
        assert.throws(() => page.applyCloudflareConfig(config(overrides), 2), { message: t('cloudflare_security.invalid_response') });
        assert.equal(page.cfConfig, previous);
        assert.equal(page.cloudflareActiveIPCount(), '4');
    }
});

test('remote or coverage errors never show a rule-created status or a success notice', async () => {
    for (const overrides of [
        { sync_status: 'error', last_error: 'quota exceeded' },
        { last_error: 'read-back failed' }, { coverage_error: 'alias outside zone' },
    ]) {
        const { page, t, standbyShown } = setup(async () => ok(config(overrides)));
        await page.loadCloudflare();
        assert.equal(page.cloudflareStatusLabel(), t('cloudflare_security.status_error'));
        assert.equal(standbyShown(), false);
        assert.equal(await page.syncCloudflare(), false);
        assert.equal(page.cfNotice, '');
        assert.equal(page.cfError, overrides.last_error || overrides.coverage_error);
    }
});

test('failed synchronization does not turn a previous empty rule into a fresh success claim', async () => {
    for (const failure of ['network', 'rejected', 'malformed']) {
        const { page, t, standbyShown } = setup(async (url, options) => {
            if (options.method === 'GET') return ok(config());
            if (failure === 'network') throw Error('offline');
            return failure === 'rejected' ? { success: false, message: 'permission denied' } : ok(config({ active_ip_count: '0' }));
        });
        await page.loadCloudflare();
        assert.equal(standbyShown(), true);
        assert.equal(await page.syncCloudflare(), false);
        assert.equal(page.cfNotice, '');
        assert.ok(page.cfError);
        assert.equal(page.cfConfig.rule_id, rule, 'retain existing rule ownership for cleanup');
        assert.equal(page.cloudflareStatusLabel(), t('cloudflare_security.status_error'));
        assert.equal(standbyShown(), false);
    }
});

test('disabling requires save before removal, and confirmed removal clears rule ownership', async () => {
    const { page, calls, t, ruleText, standbyShown } = setup(async (url, options) => {
        if (options.method === 'PUT') return ok(config({ enabled: false, sync_status: 'removal_required' }));
        if (url.endsWith('/sync')) return ok(config({ enabled: false, sync_status: 'disabled', rule_id: '', cleanup_required: false, covered_hostnames: [] }));
        return ok(config());
    });
    await page.loadCloudflare();
    page.cfForm.enabled = false;
    assert.equal(page.canSyncCloudflare(), false);
    await page.syncCloudflare();
    assert.equal(calls.length, 1, 'dirty configuration must be saved before rule removal');
    await page.saveCloudflare();
    assert.equal(calls[1].options.body.enabled, false);
    assert.equal(page.cloudflareStatusLabel(), t('cloudflare_security.status_removal_required'));
    assert.equal(standbyShown(), false);
    assert.equal(page.canSyncCloudflare(), true);
    assert.equal(await page.syncCloudflare(), true);
    assert.equal(page.cfNotice, t('cloudflare_security.rule_removed'));
    assert.equal(page.cloudflareStatusLabel(), t('cloudflare_security.status_disabled'));
    assert.equal(ruleText(), t('cloudflare_security.rule_pending'));
    assert.equal(page.cloudflareBindingLocked(), false);
    assert.equal(page.canSyncCloudflare(), false);
});

test('failed removal retains the rule and required cleanup without claiming it was removed', async () => {
    const { page, t } = setup(async (url, options) => options.method === 'GET'
        ? ok(config({ enabled: false, sync_status: 'removal_required' }))
        : { success: false, message: 'token expired' });
    await page.loadCloudflare();
    assert.equal(await page.syncCloudflare(), false);
    assert.equal(page.cfConfig.rule_id, rule);
    assert.equal(page.cloudflareBindingLocked(), true);
    assert.equal(page.cfNotice, '');
    assert.equal(page.cfError, 'token expired');
    assert.equal(page.cloudflareStatusLabel(), t('cloudflare_security.status_error'));
});

test('a read-only connection test changes test information, not rule ownership or sync state', async () => {
    const { page, calls, t, standbyShown } = setup(async url => ok(url.endsWith('/test')
        ? { site_id: 2, scope: 'shared_web_bans', zone_id: zone, zone_name: 'example.com', website_hostnames: ['shop.example.com'] }
        : config({ rule_id: '', cleanup_required: false, sync_status: 'pending', active_ip_count_known: false })));
    await page.loadCloudflare();
    const before = page.cfConfig;
    assert.equal(await page.testCloudflare(), true);
    assert.equal(page.cfConfig, before);
    assert.equal(page.cfConfig.rule_id, '');
    assert.equal(page.cloudflareStatusLabel(), t('cloudflare_security.status_pending'));
    assert.equal(page.cloudflareActiveIPCount(), t('cloudflare_security.active_ip_count_unknown'));
    assert.equal(standbyShown(), false);
    assert.equal(page.cfNotice, t('cloudflare_security.test_success'));
    assert.equal(page.cfTestInfo.zone_id, zone);
    assert.equal(calls[1].url, '/websites/2/cloudflare-security/test');
    assert.equal(calls[1].options.method, 'POST');
});

test('a stale or aborted request cannot overwrite another website or report a sync success', async () => {
    let resolve;
    const pending = new Promise(done => { resolve = done; });
    const { page } = setup(async (url, options) => options.method === 'GET' ? ok(config()) : pending);
    await page.loadCloudflare();
    const syncing = page.syncCloudflare();
    page.resetCloudflare();
    page.site = { id: 3, domain: 'other.example.com' };
    resolve(ok(config()));
    assert.equal(await syncing, false);
    assert.equal(page.cfLoaded, false);
    assert.equal(page.cfNotice, '');
    assert.equal(page.cfError, '');
    assert.equal(page.cfConfig.rule_id, undefined);
});
