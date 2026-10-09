const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const {test} = require('node:test');

const source = fs.readFileSync(path.join(__dirname, '../../web/js/app.js'), 'utf8');
const apiSource = source.slice(source.indexOf('function api('), source.indexOf('const __apiGetCache'));
const friendlySource = source.slice(source.indexOf('function friendlyAPIError('), source.indexOf('function formatBytes('));
const reply = (status = 200, data = {success:true, data:{}}) => ({status, ok:status < 400, headers:{get:() => 'application/json'}, json:async () => data});
function harness() {
    const calls = [], toasts = [], timers = new Map(); let timerID = 0;
    const context = {
        AbortController, FormData, t:key => key, document:{body:{dataset:{panelPrefix:'/panel'}}, querySelector:() => null},
        window:{location:{href:''}}, console:{error() {}}, showToast:(...args) => toasts.push(args),
        setTimeout(fn) { const id = ++timerID; timers.set(id, fn); return id; }, clearTimeout:id => timers.delete(id),
        fetch(url, options) {
            let resolve, reject;
            const promise = new Promise((a, b) => { resolve = a; reject = b; });
            calls.push({url, options, resolve, reject});
            return promise;
        },
    };
    vm.createContext(context); vm.runInContext(apiSource + friendlySource, context);
    return {context, calls, toasts, timers};
}
function rejectOnAbort(call) {
    const reject = () => call.reject(call.options.signal.reason);
    if (call.options.signal.aborted) reject();
    else call.options.signal.addEventListener('abort', reject, {once:true});
}

for (const timeout of [0, 20000]) {
    test('Chrome caller abort is silent without requiring silent:true (timeout ' + timeout + ')', async () => {
        const {context, calls, toasts, timers} = harness(), controller = new AbortController();
        const pending = context.api('/websites/1/maintenance', {signal:controller.signal, timeout});
        rejectOnAbort(calls[0]);
        controller.abort(new DOMException('signal is aborted without reason', 'AbortError'));
        await assert.rejects(pending, error => error.name === 'AbortError' && error.cancelled === true && error.code === 'request_cancelled' && error.message === 'common.request_cancelled');
        assert.deepEqual(toasts, []); assert.equal(timers.size, 0); assert.equal(context.window.location.href, '');
    });
}

for (const reason of [new Error('view destroyed'), 'view changed']) {
    test('custom caller abort reason stays a silent structured cancellation: ' + String(reason), async () => {
        const {context, calls, toasts} = harness(), controller = new AbortController();
        const pending = context.api('/websites/1/logs', {signal:controller.signal, timeout:20000});
        rejectOnAbort(calls[0]); controller.abort(reason);
        await assert.rejects(pending, error => error.cancelled === true);
        assert.equal(calls[0].options.signal.reason, reason); assert.deepEqual(toasts, []);
    });
}

test('a pre-cancelled request never starts a timeout or emits a toast', async () => {
    const {context, calls, toasts, timers} = harness(), controller = new AbortController(); controller.abort();
    const pending = context.api('/websites/1/logs', {signal:controller.signal, timeout:20000});
    rejectOnAbort(calls[0]); await assert.rejects(pending, error => error.cancelled === true);
    assert.equal(timers.size, 0); assert.deepEqual(toasts, []);
});

test('timeout has its own friendly error and one toast; it does not abort the caller', async () => {
    const {context, calls, toasts, timers} = harness(), controller = new AbortController();
    const pending = context.api('/websites/1/logs', {signal:controller.signal, timeout:20000}); rejectOnAbort(calls[0]);
    [...timers.values()][0]();
    await assert.rejects(pending, error => error.message === 'common.request_timeout' && error.code === 'request_timeout' && !error.cancelled);
    assert.equal(controller.signal.aborted, false); assert.equal(timers.size, 0);
    assert.deepEqual(toasts, [['common.request_timeout','error']]);
});

for (const trigger of ['caller cancellation', 'timeout']) {
    test('a true network rejection remains a network failure when followed by ' + trigger, async () => {
        const {context, calls, toasts, timers} = harness(), controller = new AbortController();
        const pending = context.api('/websites/1/logs', {signal:controller.signal, timeout:20000});
        calls[0].reject(new TypeError('Failed to fetch'));
        if (trigger === 'timeout') [...timers.values()][0](); else controller.abort();
        await assert.rejects(pending, error => error.message === 'common.network_error' && !error.cancelled && error.code !== 'request_timeout');
        assert.deepEqual(toasts, [['common.network_error','error']]); assert.equal(timers.size, 0);
    });
}

test('a stale response received after cancellation cannot redirect an active view', async () => {
    const {context, calls, toasts} = harness(), controller = new AbortController();
    const pending = context.api('/websites/1/logs', {signal:controller.signal});
    controller.abort(); calls[0].resolve(reply(401, {success:false, message:'expired'}));
    await assert.rejects(pending, error => error.cancelled === true);
    assert.equal(context.window.location.href, ''); assert.deepEqual(toasts, []);
});

test('cancelling while the response body is pending discards even an otherwise successful response', async () => {
    const {context, calls, toasts} = harness(), controller = new AbortController(); let resolveBody;
    const pending = context.api('/websites/1/logs', {signal:controller.signal});
    calls[0].resolve({...reply(), json:() => new Promise(resolve => { resolveBody = resolve; })});
    await new Promise(resolve => setImmediate(resolve));
    controller.abort(); resolveBody({success:true, data:{content:'old log'}});
    await assert.rejects(pending, error => error.cancelled === true); assert.deepEqual(toasts, []);
});

test('friendly abort display uses DOMException.name rather than browser-specific English text', () => {
    const {context} = harness();
    assert.equal(context.friendlyAPIError(new DOMException('signal is aborted without reason', 'AbortError')), 'common.request_cancelled');
    assert.equal(context.friendlyAPIError(new Error('Permission denied')), 'Permission denied');
});
