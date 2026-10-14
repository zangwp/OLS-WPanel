const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const { test } = require('node:test');

function setup() {
    const source = fs.readFileSync(path.join(__dirname, '../../web/templates/ai_diagnostics.html'), 'utf8');
    const script = source.match(/<script>([\s\S]*?)<\/script>/)[1].replace(/{{[\s\S]*?}}/g, 'translated');
    const calls = [], timers = new Set();
    const context = {
        AbortController, URLSearchParams, Date, t: key => key, showToast: () => {},
        window: { location: { search: '' } }, document: { body: { dataset: { panelPrefix: '/fixture' } } },
        setInterval: fn => { timers.add(fn); return fn; }, clearInterval: fn => timers.delete(fn),
        api: async (url, options) => { calls.push({ url, options }); return { success: true, data: { status: 'completed' } }; }
    };
    vm.createContext(context);
    vm.runInContext(script, context);
    const page = context.aiDiagnosticsPage();
    page.selectedSiteID = '1';
    return { page, calls, timers, context };
}

test('custom diagnosis validates an empty or oversized question before an API call', async () => {
    const { page, calls, timers } = setup();
    page.symptom = 'custom';
    page.question = ' \n\t ';
    await page.runDiagnosis();
    assert.equal(page.error, 'ai_diagnostics.question_required');
    page.question = '问'.repeat(2001);
    await page.runDiagnosis();
    assert.equal(page.error, 'ai_diagnostics.question_too_long');
    page.symptom = 'site_500';
    await page.runDiagnosis();
    assert.equal(page.error, 'ai_diagnostics.question_too_long');
    assert.equal(calls.length, 0);
    assert.equal(timers.size, 0);
    assert.equal(page.diagnosing, false);
});

test('custom and preset diagnoses submit descriptions while all six old requests remain compatible', async () => {
    const { page, calls } = setup();
    assert.equal(page.symptoms.length, 6);
    for (const item of page.symptoms) {
        page.symptom = item.value;
        page.question = '';
        await page.runDiagnosis();
        const body = calls.findLast(call => call.options?.method === 'POST').options.body;
        assert.equal(body.symptom, item.value);
        assert.equal(Object.hasOwn(body, 'question'), false);
    }
    for (const symptom of ['custom', 'performance']) {
        page.symptom = symptom;
        page.question = '  插件更新后后台变慢 \n ';
        await page.runDiagnosis();
        const body = calls.findLast(call => call.options?.method === 'POST').options.body;
        assert.equal(body.symptom, symptom);
        assert.equal(body.question, '插件更新后后台变慢');
    }
});

test('question limit counts Unicode characters and changing sites clears the previous site description', async () => {
    const { page, calls } = setup();
    page.symptom = 'custom';
    page.question = '😀'.repeat(2000);
    await page.runDiagnosis();
    assert.equal(calls.find(call => call.options?.method === 'POST').options.body.question, page.question);
    page.selectedSiteID = '2';
    await page.onSiteChange();
    assert.equal(page.question, '');
});

test('history exposes the original description separately without replacing the new question draft', async () => {
    const { page, context } = setup();
    page.question = '新的问题';
    context.api = async url => ({ success: true, data: url.endsWith('/messages') ? [] : { site_id: 1, question: '旧的问题', report: { summary: '已完成' } } });
    page.$nextTick = () => {};
    page.$refs = {};
    await page.loadSession(10);
    assert.equal(page.sessionDetail.question, '旧的问题');
    assert.equal(page.question, '新的问题');
    assert.equal(page.symptomLabel('custom'), 'ai_diagnostics.symptom_custom');
});
