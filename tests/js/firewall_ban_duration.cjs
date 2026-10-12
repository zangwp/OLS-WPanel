const fs = require('fs'), vm = require('vm'), assert = require('assert');
const controller = fs.readFileSync('web/templates/firewall_controller.html', 'utf8').match(/<script>([\s\S]*?)<\/script>/)[1];
const template = fs.readFileSync('web/templates/firewall.html', 'utf8');
const registry = fs.readFileSync('internal/router/router.go', 'utf8');
assert(template.includes('banLevelText(ban.ban_level, ban)'), 'current rows must use their actual receipt timestamps');
assert(template.includes('banLevelText(h.ban_level, h)'), 'history rows must preserve their own duration');
assert(registry.includes('"firewall.ban_level_duration"'), 'duration translation must be available to runtime JS');
let checks = 0;
for (const locale of ['zh-CN', 'en-US']) {
    const dictionary = JSON.parse(fs.readFileSync(`internal/i18n/locales/${locale}.json`, 'utf8'));
    const context = {
        currentLocale: () => locale,
        t(key, params = {}) {
            const value = key.split('.').reduce((value, segment) => value?.[segment], dictionary);
            assert.equal(typeof value, 'string', `missing translation ${locale}: ${key}`);
            return value.replace(/\{\{(\w+)\}\}/g, (_, name) => params[name] ?? `{{${name}}}`);
        }
    };
    vm.createContext(context); vm.runInContext(controller, context);
    const component = context.firewallManager('bans');
    const expect = (row, count, unit) => {
        const duration = new Intl.NumberFormat(locale, {style: 'unit', unit, unitDisplay: 'long'}).format(count);
        assert.equal(component.banLevelText(4, row), context.t('firewall.ban_level_duration', {duration}));
        checks++;
    };
    expect({banned_at: '2026-10-01T08:00:00Z', expires_at: '2026-10-08T08:00:00Z'}, 7, 'day');
    expect({banned_at: '2026-10-01T08:00:00Z', expires_at: '2026-10-31T08:00:00Z'}, 30, 'day');
    expect({banned_at: '2026-10-01 08:00:00', expires_at: '2026-10-08 08:00:00'}, 7, 'day');
    expect({banned_at: '2026-10-01T08:00:00.200Z', expires_at: '2026-10-08T08:00:00.000Z'}, 7, 'day');
    expect({banned_at: '2026-10-01T16:00:00+08:00', expires_at: '2026-10-08T08:00:00Z'}, 7, 'day');
    expect({banned_at: '2026-10-01T08:00:00Z', expires_at: '2026-10-02T20:00:00Z'}, 36, 'hour');
    for (const row of [null, {}, {banned_at: 'invalid', expires_at: 'invalid'}, {banned_at: '2026-10-08T08:00:00Z', expires_at: '2026-10-01T08:00:00Z'}, {banned_at: '2026-10-01T08:00:00Z', expires_at: null}]) {
        assert.equal(component.banLevelText(4, row), dictionary.firewall.ban_level_30d, 'unknown duration must not invent a 7-day or 30-day ban');
        checks++;
    }
    assert.equal(component.banLevelText(5, {banned_at: '2026-10-01T08:00:00Z', expires_at: '2026-10-08T08:00:00Z'}), dictionary.firewall.ban_level_permanent);
    assert.equal(component.banLevelText(2), dictionary.firewall.ban_level_10m);
    assert(!/30/.test(component.banLevelText(4)), 'severity filter must not claim every extended ban lasts 30 days');
    checks += 3;
}
console.log(`Firewall ban-duration mapping: ${checks} checks passed (both locales, real 7/30-day history, UTC/offsets, sub-second rounding, missing metadata).`);
