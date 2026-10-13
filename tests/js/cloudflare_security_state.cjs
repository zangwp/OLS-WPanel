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
    const calls = [], watchers = new Map(), messages = locale(language), t = key => lookup(messages, key);
    const context = {
        AbortController, currentLocale: () => language, t,
        api: async (url, options) => { calls.push({ url, options }); return respond(url, options); },
    };
    vm.createContext(context);
    vm.runInContext(source, context);
    const page = context.siteCloudflareSecurity();
    page.site = { id: 2, domain: 'shop.example.com' };
    page.$watch = (key, callback) => watchers.set(key, callback);
    const evaluate = expression => vm.runInNewContext(expression, {
        t, ...Object.fromEntries(Object.entries(page).map(([key, value]) => [key, typeof value === 'function' ? value.bind(page) : value])),
    });
    const expressions = [...html.matchAll(/\bx-text="([^"]*)"/g)].map(match => match[1]);
    const ruleText = () => evaluate(expressions.find(value => value.startsWith('cfConfig.rule_id')));
    const standbyShown = () => evaluate(html.match(/x-show="([^"]*cloudflareStatus\(\)[^"]*)"/)[1]);
    const execute = statement => vm.runInNewContext('with (page) { ' + statement + ' }', { page, t });
    const change = (key, value) => {
        const parts = key.split('.'), last = parts.pop();
        parts.reduce((target, part) => target[part], page)[last] = value;
        watchers.get(key)?.(value);
    };
    return { page, calls, t, context, ruleText, standbyShown, evaluate, execute, change };
}

const markup = html.replace(/{{[\s\S]*?}}/g, 'translated');
const inputTag = id => markup.match(new RegExp('<input\\b[^>]*\\bid="' + id + '"[^>]*>'))[0];
const toggleTag = id => [...markup.matchAll(/<button\b[^>]*>/g)].map(match => match[0]).find(tag => tag.includes('aria-controls="' + id + '"'));
const attribute = (tag, name) => tag.match(new RegExp('(?:^|\\s)' + name + '="([^"]*)"'))?.[1];
const noticeTag = markup.match(/<p\b[^>]*class="site-cloudflare-notice"[^>]*>/)[0];
const errorTag = markup.match(/<p\b[^>]*class="site-cloudflare-error"[^>]*x-show="cfError"[^>]*>/)[0];

test('Account ID and Token inputs are masked by default and account visibility never changes the submitted ID', async () => {
    const f = setup();
    for (const id of ['cf-account-id', 'cf-api-token']) {
        assert.equal(attribute(inputTag(id), 'type'), 'password', 'Credentials are masked even before Alpine initializes.');
        assert.equal(f.evaluate(attribute(inputTag(id), ':type')), 'password');
        assert.equal(attribute(toggleTag(id), 'type'), 'button', 'Showing a value must not submit the form.');
    }
    await f.page.loadCloudflare();
    assert.equal(f.page.cfForm.account_id, account);
    assert.equal(f.evaluate(attribute(inputTag('cf-account-id'), ':disabled')), true, 'An existing rule keeps account rebinding locked.');
    assert.equal(attribute(toggleTag('cf-account-id'), ':disabled'), undefined, 'A locked account can still be inspected.');
    f.execute(attribute(toggleTag('cf-account-id'), '@click'));
    assert.equal(f.evaluate(attribute(inputTag('cf-account-id'), ':type')), 'text');
    assert.equal(f.evaluate(attribute(toggleTag('cf-account-id'), ':aria-pressed')), true);
    assert.equal(f.evaluate(attribute(toggleTag('cf-account-id'), 'x-text')), f.t('cloudflare_security.hide_value'));
    f.execute(attribute(toggleTag('cf-account-id'), '@click'));
    assert.equal(f.evaluate(attribute(inputTag('cf-account-id'), ':type')), 'password');
    await f.page.saveCloudflare();
    assert.equal(f.calls[1].options.body.account_id, account);
    assert.equal(Object.hasOwn(f.calls[1].options.body, 'api_token'), false);
});

test('saved Token never populates the field or becomes readable; only a newly typed value can be shown', async () => {
    const f = setup(async () => ok(config({ api_token: 'must-never-read-server-token', token_ciphertext: 'must-never-read-ciphertext' })));
    await f.page.loadCloudflare();
    assert.equal(f.page.cfToken, '');
    assert.equal(f.page.cfConfig.api_token, undefined);
    assert.equal(f.page.cfConfig.token_ciphertext, undefined);
    assert.equal(f.evaluate(attribute(toggleTag('cf-api-token'), 'x-show')), false);
    assert.equal(f.evaluate(attribute(inputTag('cf-api-token'), ':placeholder')), f.t('cloudflare_security.token_keep'));
    f.page.cfToken = 'new-local-token-only-1234567890';
    assert.equal(f.evaluate(attribute(toggleTag('cf-api-token'), 'x-show')), true);
    f.execute(attribute(toggleTag('cf-api-token'), '@click'));
    assert.equal(f.evaluate(attribute(inputTag('cf-api-token'), ':type')), 'text');
    assert.equal(f.page.cfToken, 'new-local-token-only-1234567890');
    await f.page.saveCloudflare();
    assert.equal(f.calls[1].options.body.api_token, 'new-local-token-only-1234567890');
    assert.equal(f.calls[1].options.body.account_id, account);
    assert.equal(f.page.cfToken, '');
    assert.equal(f.evaluate(attribute(toggleTag('cf-api-token'), 'x-show')), false);
    assert.equal(f.evaluate(attribute(inputTag('cf-api-token'), ':type')), 'password');
    assert.equal(f.page.cfNotice, f.t('cloudflare_security.saved'));
    assert.equal(f.page.cfNoticeType, 'success', 'Saved configuration is distinct from claiming a completed sync.');
    await f.page.testCloudflare();
    assert.equal(Object.hasOwn(f.calls[2].options.body, 'api_token'), false, 'Blank field asks the backend to use its saved Token.');
});

test('clearing a displayed Token resets concealment before another Token is entered', () => {
    const f = setup();
    f.page.detailTab = 'overview'; f.page.init();
    f.change('cfToken', 'local-token-1234567890');
    f.execute(attribute(toggleTag('cf-api-token'), '@click'));
    assert.equal(f.evaluate(attribute(inputTag('cf-api-token'), ':type')), 'text');
    f.change('cfToken', '');
    assert.equal(f.evaluate(attribute(toggleTag('cf-api-token'), 'x-show')), false);
    f.change('cfToken', 'replacement-token-1234567890');
    assert.equal(f.evaluate(attribute(inputTag('cf-api-token'), ':type')), 'password');
});

test('tab changes, resets, website changes, reads and destruction conceal values without changing binding data', async () => {
    const f = setup();
    f.page.detailTab = 'overview'; f.page.init();
    await f.page.loadCloudflare();
    f.page.cfToken = 'local-unsaved-token-1234567890';
    f.page.cfShowAccount = true; f.page.cfShowToken = true;
    f.change('detailTab', 'overview');
    assert.equal(f.page.cfShowAccount, false); assert.equal(f.page.cfShowToken, false);
    assert.equal(f.page.cfForm.account_id, account);
    assert.equal(f.page.cfToken, 'local-unsaved-token-1234567890', 'Leaving a tab conceals the unsaved draft without silently submitting it.');
    f.change('detailTab', 'security');
    assert.equal(f.page.cfShowAccount, false); assert.equal(f.page.cfShowToken, false);
    f.page.cfShowAccount = true; f.page.cfShowToken = true;
    await f.page.loadCloudflare();
    assert.equal(f.page.cfShowAccount, false); assert.equal(f.page.cfShowToken, false);
    f.page.cfShowAccount = true; f.page.cfShowToken = true;
    f.page.resetCloudflare();
    assert.equal(f.page.cfShowAccount, false); assert.equal(f.page.cfShowToken, false); assert.equal(f.page.cfToken, '');
    await f.page.loadCloudflare();
    f.page.cfShowAccount = true; f.page.cfShowToken = true; f.page.cfToken = 'another-draft';
    f.page.detailTab = 'overview'; f.change('site.id', 3);
    assert.equal(f.page.cfShowAccount, false); assert.equal(f.page.cfShowToken, false); assert.equal(f.page.cfToken, '');
    assert.equal(f.page.cfForm.account_id, ''); assert.equal(f.page.cfLoaded, false);
    f.page.cfShowAccount = true; f.page.cfShowToken = true; f.page.cfToken = 'discard-on-destroy';
    f.page.destroy();
    assert.equal(f.page.cfShowAccount, false); assert.equal(f.page.cfShowToken, false); assert.equal(f.page.cfToken, '');
});

test('sync notices distinguish success, pending and actionable warnings, and failures use the error panel', async () => {
    const cases = [
        [config(), 'success', 'status_ready'],
        [config({ active_ip_count: 2 }), 'success', 'status_synced'],
        [config({ sync_status: 'pending' }), 'info', 'status_pending'],
        [config({ rule_id: '', cleanup_required: false }), 'warning', 'status_rule_missing'],
        [config({ enabled: false, sync_status: 'removal_required' }), 'warning', 'status_removal_required'],
        [config({ enabled: false, rule_id: '', cleanup_required: false, sync_status: 'disabled' }), 'success', 'rule_removed'],
    ];
    for (const [returned, kind, key] of cases) {
        const f = setup(async (_url, options) => ok(options.method === 'GET' ? config() : returned));
        await f.page.loadCloudflare();
        assert.equal(await f.page.syncCloudflare(), true);
        assert.equal(f.page.cfNotice, f.t('cloudflare_security.' + key));
        assert.equal(f.evaluate(attribute(noticeTag, ':class')), 'is-' + kind);
        assert.equal(Boolean(f.evaluate(attribute(noticeTag, 'x-show'))), true);
        assert.equal(Boolean(f.evaluate(attribute(errorTag, 'x-show'))), false);
    }
    const f = setup(async (_url, options) => options.method === 'GET' ? ok(config()) : { success: false, message: 'denied' });
    await f.page.loadCloudflare();
    f.page.cfNotice = 'old success'; f.page.cfNoticeType = 'success';
    assert.equal(await f.page.syncCloudflare(), false);
    assert.equal(Boolean(f.evaluate(attribute(noticeTag, 'x-show'))), false);
    assert.equal(f.evaluate(attribute(errorTag, 'x-show')), 'denied');
    const css = fs.readFileSync(path.join(__dirname, '../../web/css/site-security.css'), 'utf8');
    for (const [selector, token] of [['.site-cloudflare-notice', 'accent'], ['.site-cloudflare-notice.is-success', 'success'], ['.site-cloudflare-notice.is-warning', 'warning'], ['.site-cloudflare-error', 'danger']]) {
        const block = css.match(new RegExp('(?:^|\\n)' + selector.replaceAll('.', '\\.') + ' \\{([^}]+)\\}'))[1];
        assert(block.includes('color: var(--panel-' + token + ')'));
    }
});

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
    assert.equal(page.cfNoticeType, 'success', 'A successful read-only connection test has its own green result.');
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
