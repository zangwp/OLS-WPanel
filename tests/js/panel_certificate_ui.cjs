const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const { test } = require('node:test');

const source = [...fs.readFileSync(path.join(__dirname, '../../web/templates/settings.html'), 'utf8').matchAll(/<script[^>]*>([\s\S]*?)<\/script>/g)]
    .map(match => match[1].replace(/{{[\s\S]*?}}/g, 'translated')).join('\n');
const locales = Object.fromEntries(['zh-CN', 'en-US'].map(locale => [locale, JSON.parse(fs.readFileSync(path.join(__dirname, '../../internal/i18n/locales/' + locale + '.json'), 'utf8'))]));

function setup(locale = 'zh-CN') {
    const calls = [];
    const context = {
        t: key => key.split('.').reduce((value, segment) => value?.[segment], locales[locale]) || key,
        currentLocale: () => locale, showToast() {}, confirmModal: async () => true,
        setInterval: () => 1, clearInterval() {}, document: { hidden: false },
        api: async (url, options) => { calls.push({ url, options }); return { success: true, data: { port: 7543, uses_tls: true, running: false } }; },
    };
    vm.createContext(context); vm.runInContext(source, context);
    return { page: context.panelCertificateSettings(), context, calls };
}

test('panel entry shows its actual port and protocol, without a guessed 8443 default', async () => {
    const { page } = setup();
    assert.equal(page.panelEndpointLabel(), '--');
    await page.refresh();
    assert.equal(page.panelEndpointLabel(), '7543 / HTTPS');
    page.status = { port: 8080, uses_tls: false };
    assert.equal(page.panelEndpointLabel(), '8080 / HTTP');
    page.status.port = 0;
    assert.equal(page.panelEndpointLabel(), '--');
});

test('certificate expiry is readable in either language and invalid dates are not printed', () => {
    for (const locale of ['zh-CN', 'en-US']) {
        const { page } = setup(locale);
        const value = page.formatCertificateTime('2026-12-09T08:35:00Z');
        assert(value.includes('2026'));
        assert(!value.includes('T08:35:00Z'));
        assert.equal(page.formatCertificateTime('not-a-date'), '--');
        assert.equal(page.formatCertificateTime(''), '--');
    }
});

test('domain failures explain port 80 and DNS rather than printing a network exception', async () => {
    for (const locale of ['zh-CN', 'en-US']) {
        const { page, context } = setup(locale);
        page.domain = 'panel.example.test';
        context.api = async () => { throw Object.assign(new Error('GET http://[2001:db8::1]/.well-known/acme-challenge/example: EOF'), { code: 'panel_domain_http_unreachable', details: { address: '2001:db8::1', address_family: 'IPv6' } }); };
        await page.check();
        assert(page.message.includes('80'));
        assert(page.message.includes('DNS'));
        assert(!page.message.includes('EOF'));
        assert(!page.message.includes('.well-known'));
        assert(page.certificateErrorDetails().includes('2001:db8::1'));
        assert(page.certificateErrorDetails().includes('IPv6'));
        assert(!page.certificateErrorDetails().includes('{'));
        assert.equal(page.verified, false);
        assert.equal(page.checking, false);
    }
});

test('status errors use the same friendly text and retain diagnostic details', () => {
    const { page } = setup();
    page.status = { error: 'unexpected server challenge content', error_code: 'panel_domain_challenge_mismatch', error_details: { address_family: 'IPv4', address: '203.0.113.4' } };
    assert(page.certificateErrorMessage().includes('A 和 AAAA'));
    assert(!page.certificateErrorMessage().includes('unexpected'));
    assert(page.certificateErrorDetails().includes('203.0.113.4'));
    page.status = { renewal_error: 'The renewal provider is unavailable.' };
    assert.equal(page.certificateErrorMessage(), 'The renewal provider is unavailable.');
});

test('certificate source distinguishes the initial self-signed certificate', () => {
    const { page } = setup('en-US');
    page.status.certificate_source = 'self_signed';
    assert.equal(page.certificateSourceLabel(), 'Self-signed certificate');
    page.status.certificate_source = 'lets_encrypt';
    assert.equal(page.certificateSourceLabel(), "Let's Encrypt");
    page.status.certificate_source = 'custom';
    assert.equal(page.certificateSourceLabel(), 'Custom certificate');
});

test('a successful check clears prior errors and sends only the entered domain', async () => {
    const { page, calls } = setup();
    page.domain = 'panel.example.test'; page.errorDetails = { address: '203.0.113.4' };
    await page.check();
    assert.equal(calls[0].url, '/settings/panel-domain/check');
    assert.equal(calls[0].options.body.domain, 'panel.example.test');
    assert.equal(calls[0].options.timeout, 45000);
    assert.equal(page.verified, true);
    assert.equal(page.errorDetails, null);
});

test('double checks and a running certificate request cannot submit duplicate checks', async () => {
    const { page, context } = setup();
    let resolve, requests = 0;
    context.api = () => { requests++; return new Promise(done => { resolve = done; }); };
    const pending = page.check();
    await page.check(); assert.equal(requests, 1);
    resolve({ success: true, data: {} }); await pending;
    page.status.running = true;
    await page.check(); assert.equal(requests, 1);
});

test('unsupported old error responses keep their readable fallback', async () => {
    const { page, context } = setup();
    context.api = async () => { throw new Error('域名解析暂时不可用'); };
    await page.check();
    assert.equal(page.message, '域名解析暂时不可用');
    assert.equal(page.verified, false);
});

test('a completed check cannot mark an edited domain verified', async () => {
    const { page, context } = setup();
    let resolve;
    page.domain = 'old.example.test';
    context.api = () => new Promise(done => { resolve = done; });
    const pending = page.check();
    page.domain = 'new.example.test'; page.invalidateDomainVerification();
    resolve({ success: true, data: {} }); await pending;
    assert.equal(page.domain, 'new.example.test');
    assert.equal(page.verified, false);
    assert.equal(page.message, '');
    assert.equal(page.checking, false);
});

test('the initial status response does not overwrite a domain typed while loading', async () => {
    const { page, context } = setup();
    let resolve;
    context.api = () => new Promise(done => { resolve = done; });
    const pending = page.init();
    page.domain = 'draft.example.test'; page.invalidateDomainVerification();
    resolve({ success: true, data: { domain: 'installed.example.test' } }); await pending;
    assert.equal(page.domain, 'draft.example.test');
    page.destroy();
});

test('certificate confirmation guards repeated clicks before the dialog resolves', async () => {
    const { page, context, calls } = setup();
    let confirm;
    context.confirmModal = () => new Promise(done => { confirm = done; });
    const pending = page.apply();
    assert.equal(page.starting, true);
    await page.apply();
    confirm(false); await pending;
    assert.equal(calls.length, 0);
    assert.equal(page.starting, false);
});
