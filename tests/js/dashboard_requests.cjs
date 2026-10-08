const fs = require('fs');
const path = require('path');
const vm = require('vm');
const assert = require('assert');

const html = fs.readFileSync(path.join(__dirname, '../../web/templates/dashboard.html'), 'utf8');
const code = [...html.matchAll(/<script[^>]*>([\s\S]*?)<\/script>/g)]
    .map(match => match[1].replace(/{{[\s\S]*?}}/g, 'null')).join('\n');
const pending = [];
let chart;
const context = {
    window: {}, console, t: key => key,
    document: { getElementById: () => ({ getContext: () => ({}) }) },
    api: url => new Promise(resolve => pending.push({ url, resolve })),
    Chart: function (_canvas, options) {
        chart = this;
        this.data = options.data;
        this.updates = 0;
        this.update = () => this.updates++;
    },
};
const response = label => ({ success: true, data: { labels: [label], cpu: [1], memory: [2], load: [3] } });
vm.createContext(context);
vm.runInContext(code, context);

(async () => {
    const week = context.window.fetchMetrics('7d');
    const fortnight = context.window.fetchMetrics('15d');
    pending[2].resolve(response('15d'));
    await fortnight;
    pending[1].resolve(response('7d'));
    await week;
    // Even the initial chart load may finish after the user changes the range.
    pending[0].resolve(response('24h'));
    await new Promise(resolve => setImmediate(resolve));
    assert.deepStrictEqual(chart.data.labels, ['15d']);
    assert.equal(chart.updates, 1);
    const day = context.window.fetchMetrics('24h');
    pending[3].resolve(response('new 24h'));
    await day;
    assert.deepStrictEqual(chart.data.labels, ['new 24h']);
    assert.equal(chart.updates, 2);
    console.log('Dashboard ignores stale range and initial-load responses.');
})().catch(error => { console.error(error); process.exitCode = 1; });
