const fs = require('fs');
const path = require('path');
const vm = require('vm');
const assert = require('node:assert/strict');
const { test } = require('node:test');

const html = fs.readFileSync(path.join(__dirname, '../../web/templates/dashboard.html'), 'utf8');
const code = [...html.matchAll(/<script[^>]*>([\s\S]*?)<\/script>/g)]
    .map(match => match[1].replace(/{{[\s\S]*?}}/g, 'null')).join('\n');
const flush = () => new Promise(resolve => setImmediate(resolve));
const history = label => ({ success: true, data: { labels: [label], cpu: [1], memory: [2], load: [3] } });
const firstSites = [{ site_id: 1, domain: 'one.example', cpu: 1, mem: 2, proc_count: 3 }];
const sampledAt = '2026-10-13T08:15:10Z';
const statsData = (overrides = {}) => ({ cpu_percent: 64.4, memory_percent: 69.8, memory_used_bytes: 698, memory_total_bytes: 1000,
    swap_used_bytes: 0, swap_total_bytes: 0, disk_used_bytes: 100, disk_total_bytes: 1000, load_avg_1: 1, load_avg_5: 0.5, load_avg_15: 0.1, uptime: 25020, ...overrides });

function fixture(timeZone = 'Asia/Shanghai', locale = 'en-US') {
    const pending = [], intervals = new Map(), listeners = new Map(), documentListeners = new Map();
    const elements = {
        metricsCanvas: { getContext: () => ({}) },
        metricsSummary: { hidden: true, textContent: '' },
        metricsError: { hidden: true, textContent: '' },
        metricsTimezone: { hidden: true, textContent: '' },
    };
    let chart, ready, nextInterval = 0, chartCount = 0;
    const context = {
        window: {
            addEventListener(event, callback) { if (!listeners.has(event)) listeners.set(event, new Set()); listeners.get(event).add(callback); },
            removeEventListener(event, callback) { listeners.get(event)?.delete(callback); },
        }, console, AbortController,
        Intl: { DateTimeFormat: function(language, options) { return new Intl.DateTimeFormat(language || locale, { ...options, timeZone }); } },
        t: (key, values) => key + (values ? JSON.stringify(values) : ''),
        currentLocale: () => locale,
        setInterval(callback, delay) { assert.equal(delay, 30000); const id = ++nextInterval; intervals.set(id, callback); return id; },
        clearInterval(id) { intervals.delete(id); },
        document: {
            readyState: 'loading', hidden: false,
            getElementById: id => elements[id],
            addEventListener(event, callback, options) {
                if (event === 'DOMContentLoaded') { assert.equal(options.once, true); ready = callback; return; }
                if (!documentListeners.has(event)) documentListeners.set(event, new Set());
                documentListeners.get(event).add(callback);
            },
            removeEventListener(event, callback) { if (event === 'DOMContentLoaded' && ready === callback) ready = null; documentListeners.get(event)?.delete(callback); },
        },
        api: (url, options) => new Promise((resolve, reject) => {
            assert.equal(options.timeout, 15000);
            assert(options.signal, 'Dashboard reads must be cancellable.');
            pending.push({ url, options, resolve, reject });
        }),
        Chart: function(_canvas, options) {
            chart = this; chartCount++;
            this.data = options.data; this.options = options.options; this.updates = 0; this.destroyed = false;
            this.update = () => { assert(!this.destroyed); this.updates++; };
            this.destroy = () => { this.destroyed = true; };
        },
    };
    vm.createContext(context);
    vm.runInContext(code, context);
    return {
        context, pending, intervals, listeners, elements,
        get chart() { return chart; }, get chartCount() { return chartCount; },
        ready() { context.document.readyState = 'interactive'; ready?.(); },
        take(url) { const request = pending.shift(); assert(request, `Missing request ${url}`); assert.equal(request.url, url); return request; },
        tick() { for (const callback of [...intervals.values()]) callback(); },
        emit(event) { for (const callback of [...(listeners.get(event) || [])]) callback(); },
        emitDocument(event) { for (const callback of [...(documentListeners.get(event) || [])]) callback(); },
        async reply(request, response) { request.resolve(response); await flush(); },
        async fail(request, message) { request.reject(new Error(message)); await flush(); },
        format(value, options) { return new Intl.DateTimeFormat(locale, { ...options, timeZone }).format(new Date(value)); },
    };
}

test('chart waits for dependencies and repeated initialization creates one timer and request', () => {
    const f = fixture();
    assert.equal(f.chart, undefined);
    assert.equal(f.pending.length, 0);
    f.ready(); f.ready();
    assert.equal(f.chartCount, 1);
    assert.equal(f.pending.length, 1);
    assert.equal(f.intervals.size, 1);
    f.context.window.dashboardHistory().destroy();
    assert.equal(f.intervals.size, 0);
});

test('destroying the history component before dependencies are ready prevents delayed initialization', () => {
    const f = fixture();
    f.context.window.dashboardHistory().destroy();
    f.ready(); f.emit('pageshow'); f.tick();
    assert.equal(f.chartCount, 0);
    assert.equal(f.pending.length, 0);
    assert.equal(f.intervals.size, 0);
});

test('range changes cancel old reads and late responses cannot replace the selected history', async () => {
    const f = fixture(); f.ready();
    const initial = f.take('/dashboard/metrics?range=24h');
    const weekPromise = f.context.window.fetchMetrics('7d');
    const week = f.take('/dashboard/metrics?range=7d');
    const fortnightPromise = f.context.window.fetchMetrics('15d');
    const fortnight = f.take('/dashboard/metrics?range=15d');
    assert(initial.options.signal.aborted); assert(week.options.signal.aborted);
    await f.reply(fortnight, { ...history('15d'), data: { ...history('15d').data, reduced: true, sample_count: 21600, displayed_points: 900, bucket_seconds: 6513 } });
    await fortnightPromise;
    await f.reply(week, history('7d')); await weekPromise;
    await f.reply(initial, history('24h'));
    assert.deepEqual(f.chart.data.labels, ['15d']);
    assert.equal(f.chart.updates, 1);
    assert.equal(f.elements.metricsSummary.hidden, false);
    assert(f.elements.metricsSummary.textContent.includes('21600'));
});

test('history polls the selected range every 30 seconds, skips overlap and hidden tabs, and retains failed data', async () => {
    const f = fixture(); f.ready();
    const initial = f.take('/dashboard/metrics?range=24h');
    f.tick(); assert.equal(f.pending.length, 0, 'Initial read must not overlap a timer read.');
    await f.reply(initial, history('initial'));
    f.tick();
    const automatic = f.take('/dashboard/metrics?range=24h');
    f.tick(); assert.equal(f.pending.length, 0);
    f.context.window.fetchMetrics('7d');
    const week = f.take('/dashboard/metrics?range=7d');
    assert(automatic.options.signal.aborted);
    await f.reply(automatic, history('obsolete'));
    await f.fail(week, 'backend unavailable');
    assert.deepEqual(f.chart.data.labels, ['initial']);
    assert(f.elements.metricsError.textContent.includes('dashboard.data_stale'));
    f.context.document.hidden = true;
    f.tick(); assert.equal(f.pending.length, 0);
    f.context.document.hidden = false;
    f.tick();
    await f.reply(f.take('/dashboard/metrics?range=7d'), history('updated week'));
    assert.deepEqual(f.chart.data.labels, ['updated week']);
    assert.equal(f.elements.metricsError.hidden, true);
    assert.equal(f.elements.metricsSummary.hidden, true);
    f.tick();
    await f.reply(f.take('/dashboard/metrics?range=7d'), { success: false, message: 'history failed' });
    assert.deepEqual(f.chart.data.labels, ['updated week']);
    assert(f.elements.metricsError.textContent.includes('history failed'));
});

test('history pagehide pauses and cancels; pageshow resumes once; component destruction prevents timers and late writes', async () => {
    const f = fixture(); f.ready();
    const initial = f.take('/dashboard/metrics?range=24h');
    f.emit('pagehide');
    assert(initial.options.signal.aborted); assert.equal(f.intervals.size, 0);
    f.tick(); f.context.window.fetchMetrics('7d'); assert.equal(f.pending.length, 0);
    await f.reply(initial, history('after leaving'));
    assert.equal(f.chart.updates, 0);
    f.emit('pageshow'); f.emit('pageshow');
    assert.equal(f.intervals.size, 1); assert.equal(f.pending.length, 1);
    const resumed = f.take('/dashboard/metrics?range=24h');
    const component = f.context.window.dashboardHistory();
    component.destroy(); component.destroy();
    assert(resumed.options.signal.aborted); assert.equal(f.intervals.size, 0);
    await f.reply(resumed, history('after destroying'));
    assert.equal(f.chart.updates, 0); assert(f.chart.destroyed);
    f.emit('pageshow'); f.tick(); f.ready();
    assert.equal(f.pending.length, 0); assert.equal(f.chartCount, 1);
});

test('top statistics really change on the second timer sample and do not duplicate reads', async () => {
    const f = fixture(), stats = f.context.dashboardStats();
    stats.initFetch(); stats.initFetch();
    assert.equal(f.intervals.size, 1);
    const first = f.take('/dashboard/stats');
    f.tick(); await stats.fetchStats(); assert.equal(f.pending.length, 0);
    await f.reply(first, { success: true, data: statsData() });
    assert.equal(stats.stats.cpu_percent, 64.4); assert.equal(stats.loaded, true);
    f.context.document.hidden = true; f.tick(); assert.equal(f.pending.length, 0);
    f.context.document.hidden = false; f.tick();
    await f.reply(f.take('/dashboard/stats'), { success: true, data: statsData({ cpu_percent: 39.3, memory_percent: 38.2, uptime: 25050 }) });
    assert.equal(stats.stats.cpu_percent, 39.3); assert.equal(stats.stats.memory_percent, 38.2); assert.equal(stats.stats.uptime, 25050);
    f.tick(); await f.fail(f.take('/dashboard/stats'), 'stats unavailable');
    assert.equal(stats.stats.cpu_percent, 39.3); assert.equal(stats.error, 'stats unavailable');
    f.tick(); await f.reply(f.take('/dashboard/stats'), { success: false, message: 'retry later' });
    assert.equal(stats.error, 'retry later'); assert.equal(stats.stats.uptime, 25050);
    f.tick(); await f.reply(f.take('/dashboard/stats'), { success: true, data: statsData({ cpu_percent: 1, uptime: 25140 }) });
    assert.equal(stats.error, ''); assert.equal(stats.stats.cpu_percent, 1);
    stats.destroy(); assert.equal(f.intervals.size, 0);
});

test('statistics cancel across pagehide, resume after pageshow and reject replies after destruction', async () => {
    const f = fixture(), stats = f.context.dashboardStats();
    stats.initFetch();
    const first = f.take('/dashboard/stats');
    f.emit('pagehide');
    assert(first.options.signal.aborted); assert.equal(f.intervals.size, 0);
    await f.reply(first, { success: true, data: statsData({ cpu_percent: 99 }) });
    assert.equal(stats.loaded, false);
    f.emit('pageshow'); f.emit('pageshow');
    const resumed = f.take('/dashboard/stats');
    assert.equal(f.pending.length, 0); assert.equal(f.intervals.size, 1);
    stats.destroy(); stats.destroy();
    assert(resumed.options.signal.aborted);
    await f.reply(resumed, { success: true, data: statsData({ cpu_percent: 88 }) });
    assert.equal(stats.loaded, false); assert.equal(f.intervals.size, 0);
    stats.initFetch(); f.tick(); f.emit('pageshow'); await stats.fetchStats();
    assert.equal(f.pending.length, 0);
});

test('malformed statistics preserve the last confirmed sample; zero Swap remains a valid response', async () => {
    const f = fixture(), stats = f.context.dashboardStats(), valid = statsData();
    stats.initFetch();
    await f.reply(f.take('/dashboard/stats'), { success: true, data: valid });
    assert.equal(stats.stats.swap_used_bytes, 0); assert.equal(stats.stats.swap_total_bytes, 0);
    for (const data of [null, {}, [], 'invalid', statsData({ cpu_percent: '64.4' }), statsData({ memory_total_bytes: undefined }), statsData({ uptime: -1 }), statsData({ load_avg_5: NaN })]) {
        f.tick(); await f.reply(f.take('/dashboard/stats'), { success: true, data });
        assert.equal(stats.stats, valid);
        assert.equal(stats.loaded, true); assert(stats.error);
    }
    stats.destroy();
});

test('returning to a visible tab refreshes both statistics and history immediately without overlapping reads', async () => {
    const f = fixture(); f.ready();
    await f.reply(f.take('/dashboard/metrics?range=24h'), history('initial'));
    const stats = f.context.dashboardStats(); stats.initFetch();
    await f.reply(f.take('/dashboard/stats'), { success: true, data: statsData() });
    f.context.document.hidden = true; f.emitDocument('visibilitychange'); f.tick();
    assert.equal(f.pending.length, 0);
    f.context.document.hidden = false; f.emitDocument('visibilitychange');
    const nextHistory = f.take('/dashboard/metrics?range=24h'), nextStats = f.take('/dashboard/stats');
    f.emitDocument('visibilitychange'); f.tick();
    assert.equal(f.pending.length, 0, 'Visibility events and timer ticks share the same in-flight guards.');
    await f.reply(nextHistory, history('visible again'));
    await f.reply(nextStats, { success: true, data: statsData({ cpu_percent: 2 }) });
    assert.deepEqual(f.chart.data.labels, ['visible again']); assert.equal(stats.stats.cpu_percent, 2);
    stats.destroy(); f.context.window.dashboardHistory().destroy();
    f.emitDocument('visibilitychange'); f.tick();
    assert.equal(f.pending.length, 0); assert.equal(f.intervals.size, 0);
});

test('website resources preserve fresh refresh, single-flight, stale state and cancellation', async () => {
    const f = fixture(), resources = f.context.siteResources();
    const firstRead = resources.fetch();
    const first = f.take('/dashboard/site-resources');
    await resources.fetch(true); assert.equal(f.pending.length, 0);
    await f.reply(first, { success: true, data: firstSites, sampled_at: sampledAt }); await firstRead;
    assert.equal(resources.loaded, true); assert.equal(resources.loading, false);
    assert.equal(resources.since, f.format(sampledAt, { hour: '2-digit', minute: '2-digit', second: '2-digit', hourCycle: 'h23', timeZoneName: 'short' }));
    const failing = resources.fetch(true);
    await f.fail(f.take('/dashboard/site-resources?fresh=1'), 'ps failed'); await failing;
    assert.deepEqual(resources.sites, firstSites); assert.equal(resources.error, 'ps failed');
    resources.fetch(); const old = f.take('/dashboard/site-resources');
    resources.cancelRequest(); resources.fetch(true);
    assert(old.options.signal.aborted);
    const latest = [{ site_id: 2, domain: 'latest.example', cpu: 7, mem: 4, proc_count: 1 }];
    await f.reply(f.take('/dashboard/site-resources?fresh=1'), { success: true, data: latest, sampled_at: sampledAt });
    await f.reply(old, { success: true, data: firstSites });
    assert.deepEqual(resources.sites, latest);
    resources.fetch(); const destroyed = f.take('/dashboard/site-resources');
    resources.destroy(); assert(destroyed.options.signal.aborted);
    await f.reply(destroyed, { success: true, data: firstSites });
    assert.deepEqual(resources.sites, latest);
});

test('website polling initializes once and initial failure does not claim no PHP processes', async () => {
    const f = fixture(), resources = f.context.siteResources();
    resources.initFetch(); resources.initFetch();
    assert.equal(f.intervals.size, 1); assert.equal(f.pending.length, 1);
    const first = f.take('/dashboard/site-resources');
    f.emit('pagehide'); assert(first.options.signal.aborted);
    resources.destroy();
    await f.reply(first, { success: true, data: firstSites });
    assert.equal(f.intervals.size, 0); assert.equal(resources.loaded, false);
    const failed = f.context.siteResources(); failed.fetch();
    await f.fail(f.take('/dashboard/site-resources'), 'initial request failed');
    assert.equal(failed.loaded, false); assert.equal(failed.error, 'initial request failed');
    assert(html.includes('x-show="loaded && sites.length === 0"'));
});

for (const [zone, locale] of [['Asia/Shanghai', 'zh-CN'], ['America/New_York', 'en-US']]) {
    test(`${zone}: chart axis, tooltip and website sample time use the same browser timezone`, async () => {
        const f = fixture(zone, locale); f.ready();
        const timestamps = [sampledAt, '2026-10-13T16:16:10+08:00', '2026-10-13T12:15:10Z'];
        await f.reply(f.take('/dashboard/metrics?range=24h'), { success: true, data: { labels: ['08:15', '08:16', '12:15'], cpu: [1, 99, 2], memory: [20, 21, 22], load: [1, 2, 1], timestamps } });
        assert.equal(f.chart.options.scales.x.type, 'linear');
        assert.equal(f.chart.data.datasets[0].data[1].x - f.chart.data.datasets[0].data[0].x, 60000);
        assert.equal(f.chart.data.datasets[0].data[2].x - f.chart.data.datasets[0].data[1].x, 239 * 60000);
        assert.equal(f.chart.options.scales.x.ticks.callback(new Date(sampledAt).getTime()), f.format(sampledAt, { hour: '2-digit', minute: '2-digit', hourCycle: 'h23' }));
        assert.equal(f.chart.options.scales.x.ticks.callback(new Date(sampledAt).getTime()), zone === 'Asia/Shanghai' ? '16:15' : '04:15', '08:15 UTC is converted, not relabeled as local time.');
        const full = f.format(sampledAt, { year: 'numeric', month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit', second: '2-digit', hourCycle: 'h23', timeZoneName: 'short' });
        assert(f.chart.options.plugins.tooltip.callbacks.title([{ dataIndex: 0, label: '08:15' }]).includes(full));
        assert(f.elements.metricsTimezone.textContent.includes(zone));
        const resources = f.context.siteResources(); resources.fetch();
        await f.reply(f.take('/dashboard/site-resources'), { success: true, data: firstSites, sampled_at: sampledAt });
        assert.equal(resources.since, f.format(sampledAt, { hour: '2-digit', minute: '2-digit', second: '2-digit', hourCycle: 'h23', timeZoneName: 'short' }));
        f.context.window.fetchMetrics('15d');
        await f.reply(f.take('/dashboard/metrics?range=15d'), { success: true, data: { labels: ['10-13'], cpu: [1], memory: [2], load: [3], timestamps: [sampledAt] } });
        assert.equal(f.chart.options.scales.x.ticks.callback(new Date(sampledAt).getTime()), f.format(sampledAt, { month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit', hourCycle: 'h23' }));
        assert.equal(f.context.dashboardTime('invalid'), '');
    });
}
