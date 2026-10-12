const fs = require('fs');
const path = require('path');
const vm = require('vm');
const assert = require('assert');

const html = fs.readFileSync(path.join(__dirname, '../../web/templates/dashboard.html'), 'utf8');
const code = [...html.matchAll(/<script[^>]*>([\s\S]*?)<\/script>/g)]
    .map(match => match[1].replace(/{{[\s\S]*?}}/g, 'null')).join('\n');
const pending = [];
let chart;
let ready;
const elements = {
    metricsCanvas: { getContext: () => ({}) },
    metricsSummary: { hidden: true, textContent: '' },
    metricsError: { hidden: true, textContent: '' },
};
const listeners = new Map();
const intervals = new Map();
let nextInterval = 0;
const context = {
    window: {
        addEventListener(event, callback) { if (!listeners.has(event)) listeners.set(event, new Set()); listeners.get(event).add(callback); },
        removeEventListener(event, callback) { listeners.get(event)?.delete(callback); },
    }, console, AbortController,
    t: (key, values) => key + (values ? JSON.stringify(values) : ''),
    currentLocale: () => 'en-US',
    setInterval(callback) { const id = ++nextInterval; intervals.set(id, callback); return id; },
    clearInterval(id) { intervals.delete(id); },
    document: {
        readyState: 'loading',
        hidden: false,
        getElementById: id => elements[id],
        addEventListener: (event, callback, options) => {
            assert.equal(event, 'DOMContentLoaded');
            assert.equal(options.once, true);
            ready = callback;
        },
    },
    api: (url, options) => new Promise((resolve, reject) => {
        assert.equal(options.timeout, 15000);
        assert(options.signal, 'Dashboard reads must be cancellable.');
        pending.push({ url, options, resolve, reject });
    }),
    Chart: function (_canvas, options) {
        chart = this;
        this.data = options.data;
        this.options = options.options;
        this.updates = 0;
        this.update = () => this.updates++;
    },
};
const response = label => ({ success: true, data: { labels: [label], cpu: [1], memory: [2], load: [3] } });
vm.createContext(context);
vm.runInContext(code, context);
assert.equal(chart, undefined, 'Chart must not start while deferred dependencies are still loading.');
assert.equal(pending.length, 0, 'Metrics must wait for deferred dependencies.');
assert.equal(typeof ready, 'function');
context.document.readyState = 'interactive';
ready();
assert(chart, 'Chart starts once the parsed document and deferred dependencies are ready.');

(async () => {
    const week = context.window.fetchMetrics('7d');
    const fortnight = context.window.fetchMetrics('15d');
    assert(pending[0].options.signal.aborted, 'Range change cancels the initial request.');
    assert(pending[1].options.signal.aborted, 'Latest range cancels the superseded request.');
    pending[2].resolve({ ...response('15d'), data: { ...response('15d').data, reduced: true, sample_count: 21600, displayed_points: 900, bucket_seconds: 6513 } });
    await fortnight;
    assert.equal(elements.metricsSummary.hidden, false);
    assert(elements.metricsSummary.textContent.includes('21600'));
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
    assert.equal(elements.metricsSummary.hidden, true, 'Raw samples do not show a reduction notice.');

    const leavingMetrics = context.window.fetchMetrics('7d');
    for (const callback of listeners.get('pagehide')) callback();
    assert(pending[4].options.signal.aborted, 'Leaving the page cancels metric reads.');
    pending[4].resolve(response('late after leaving'));
    await leavingMetrics;
    assert.equal(chart.updates, 2);
    const failingMetrics = context.window.fetchMetrics('7d');
    pending[5].reject(new Error('backend unavailable'));
    await failingMetrics;
    assert.deepStrictEqual(chart.data.labels, ['new 24h'], 'A failed history refresh preserves prior data.');
    assert(elements.metricsError.textContent.includes('dashboard.data_stale'));

    const resources = context.siteResources();
    const firstResources = resources.fetch();
    await resources.fetch(true);
    assert.equal(pending.length, 7, 'Repeated refresh joins the existing frontend operation.');
    const firstSites = [{ site_id: 1, domain: 'one.example', cpu: 1, mem: 2, proc_count: 3 }];
    const sampledAt = '2026-10-11T08:00:00Z';
    pending[6].resolve({ success: true, data: firstSites, sampled_at: sampledAt });
    await firstResources;
    assert.equal(resources.loaded, true);
    assert.equal(resources.loading, false);
    assert.equal(resources.since, new Date(sampledAt).toLocaleTimeString('en-US'), 'Shows the server sample time, not fetch completion.');
    const failedResources = resources.fetch(true);
    assert.equal(pending[7].url, '/dashboard/site-resources?fresh=1');
    pending[7].reject(new Error('ps failed'));
    await failedResources;
    assert.deepStrictEqual(resources.sites, firstSites);
    assert.equal(resources.error, 'ps failed');
    assert.equal(resources.loaded, true);

    const oldResources = resources.fetch();
    resources.cancelRequest();
    assert(pending[8].options.signal.aborted);
    const newResources = resources.fetch(true);
    const latestSites = [{ site_id: 2, domain: 'latest.example', cpu: 7, mem: 4, proc_count: 1 }];
    pending[9].resolve({ success: true, data: latestSites, sampled_at: sampledAt });
    await newResources;
    pending[8].resolve({ success: true, data: firstSites, sampled_at: sampledAt });
    await oldResources;
    assert.deepStrictEqual(resources.sites, latestSites, 'Cancelled old response cannot overwrite the latest resource sample.');
    const destroyedResources = resources.fetch();
    resources.destroy();
    assert(pending[10].options.signal.aborted);
    pending[10].resolve({ success: true, data: firstSites });
    await destroyedResources;
    assert.deepStrictEqual(resources.sites, latestSites);

    const polling = context.siteResources();
    polling.initFetch();
    polling.initFetch();
    assert.equal(intervals.size, 1);
    assert.equal(pending.length, 12, 'Initialization does not duplicate polling or initial fetch.');
    for (const callback of listeners.get('pagehide')) callback();
    assert(pending[11].options.signal.aborted);
    polling.destroy();
    pending[11].resolve({ success: true, data: firstSites });
    await new Promise(resolve => setImmediate(resolve));
    assert.equal(intervals.size, 0);
    assert.equal(polling.loaded, false);

    const initialFailure = context.siteResources();
    const failedInitial = initialFailure.fetch();
    pending[12].reject(new Error('initial request failed'));
    await failedInitial;
    assert.equal(initialFailure.loaded, false);
    assert.equal(initialFailure.error, 'initial request failed');
    assert(html.includes('x-show="loaded && sites.length === 0"'), 'Initial failure must not claim no PHP processes.');

    const timedMetrics = context.window.fetchMetrics('15d');
    const timestamps = ['2026-10-11T16:00:00+08:00', '2026-10-11T16:01:00+08:00', '2026-10-11T20:00:00+08:00'];
    pending[13].resolve({ success: true, data: { labels: ['10-11', '10-11', '10-11'], cpu: [1, 99, 2], memory: [20, 21, 22], load: [1, 2, 1], timestamps } });
    await timedMetrics;
    assert.equal(chart.options.scales.x.type, 'linear');
    assert.equal(chart.data.datasets[0].data[1].y, 99);
    assert.equal(chart.data.datasets[0].data[1].x - chart.data.datasets[0].data[0].x, 60000);
    assert.equal(chart.data.datasets[0].data[2].x - chart.data.datasets[0].data[1].x, 239 * 60000, 'Irregular samples retain real spacing.');
    assert.equal(chart.options.scales.x.ticks.callback(new Date(timestamps[1]).getTime()), '10-11 16:01', 'Axis retains server-local time.');
    assert(chart.options.plugins.tooltip.callbacks.title([{ dataIndex: 1, label: '10-11' }]).includes('2026-10-11 16:01:00+08:00'));
    console.log('Dashboard: metric cancellation, range ordering, peak notice, resource single-flight, fresh refresh, timestamps, stale-data handling and page cleanup pass.');
})().catch(error => { console.error(error); process.exitCode = 1; });
