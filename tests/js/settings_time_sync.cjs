const fs = require('fs'), vm = require('vm'), assert = require('assert/strict'), path = require('path');
const html = fs.readFileSync(path.resolve(__dirname, '../../web/templates/settings.html'), 'utf8');
const source = [...html.matchAll(/<script[^>]*>([\s\S]*?)<\/script>/g)].map(match => match[1]).join('\n');
const controlExpressions = [...html.matchAll(/:disabled="([^"]*accountLoaded[^"]*)"/g)].map(match => match[1]);
const syncExpression = html.match(/@click="syncNTP\(\)"[^>]*:disabled="([^"]+)"/)?.[1];
assert(controlExpressions.length >= 5, 'Exercise the account buttons and settings fieldsets from the actual template.');
assert(syncExpression, 'Exercise the actual NTP button disabled expression.');
const copy = value => JSON.parse(JSON.stringify(value));
const flush = async () => { for (let i = 0; i < 5; i++) await Promise.resolve(); };

function harness() {
  let now = 1800000000000, nextTimer = 1;
  const requests = [], timers = new Map(), intervals = new Map(), notices = [];
  class Clock extends Date { static now() { return now; } }
  const context = {
    Date: Clock, AbortController, t: key => key,
    showToast(message, type) { notices.push({message, type}); },
    setTimeout(callback, delay) { const id = nextTimer++; timers.set(id, {callback, at: now + delay}); return id; },
    clearTimeout(id) { timers.delete(id); },
    setInterval(callback, delay) { const id = nextTimer++; intervals.set(id, {callback, delay}); return id; },
    clearInterval(id) { intervals.delete(id); },
    window: {location: {hash: '', href: ''}, addEventListener() {}, removeEventListener() {}},
    api(url, options = {}) {
      let resolve, reject;
      const promise = new Promise((yes, no) => { resolve = yes; reject = no; });
      // Deliberately ignore abort here: late network responses must also be harmless.
      requests.push({url, options, resolve, reject});
      return promise;
    }
  };
  vm.createContext(context);
  vm.runInContext(source, context);
  const page = context.panelSettings();
  return {
    page, requests, timers, intervals, notices,
    now: () => now,
    disabled(expression) { return vm.runInNewContext('with (page) { ' + expression + ' }', {page}); },
    advance(milliseconds) {
      const end = now + milliseconds, results = [];
      for (let count = 0; count < 20; count++) {
        const due = [...timers].filter(([, timer]) => timer.at <= end).sort((a, b) => a[1].at - b[1].at)[0];
        if (!due) { now = end; return results; }
        const [id, timer] = due;
        now = timer.at;
        timers.delete(id);
        results.push(timer.callback());
      }
      assert.fail('A time refresh must not start an unbounded background timer.');
    }
  };
}

function seedDrafts(page, suffix = 'initial') {
  Object.assign(page, {
    accountLoaded: true, accountLoadError: 'retained diagnostic ' + suffix,
    panelTitle: 'Unsaved title ' + suffix, hostname: 'draft-' + suffix,
    username: 'draft-web-' + suffix, originalUsername: 'saved-web-user', basicAuthUser: 'draft-basic-' + suffix,
    githubProxy: 'https://draft-' + suffix + '.example', timezone: 'Asia/Tokyo',
    accountSaved: true, proxyResult: 'existing proxy result ' + suffix, proxyOk: true
  });
  for (const key of Object.keys(page.pw)) page.pw[key] = 'draft-' + key + '-' + suffix;
  Object.assign(page.autoUpdate, {
    enabled: true, mode: 'all', window: '06:00-08:00', delay: 73, signatureTimeout: 44,
    lastTarget: 'draft-target-' + suffix, lastStatus: 'draft-status', lastStage: 'draft-stage',
    lastError: 'existing error', lastSuccess: 'existing date', lastSuccessVersion: 'existing version'
  });
}

const draftKeys = [
  'activeSection', 'panelTitle', 'hostname', 'username', 'originalUsername', 'basicAuthUser',
  'githubProxy', 'timezone', 'pw', 'autoUpdate', 'accountLoaded', 'accountLoadError',
  'accountSaving', 'accountSaved', 'proxyTesting', 'proxyResult', 'proxyOk'
];
const timeKeys = ['serverTimeBase', 'serverTimeFetchedAt', 'serverTime', 'ntpSynced', 'ntpEnabled', 'ntpService'];
const snapshot = (page, keys) => copy(Object.fromEntries(keys.map(key => [key, page[key]])));
const drafts = page => snapshot(page, draftKeys);
const timeState = page => snapshot(page, timeKeys);
function controlsEnabled(h) {
  assert(controlExpressions.every(expression => h.disabled(expression) === false), 'NTP work must leave unrelated account and settings controls enabled.');
}
function reply(overrides = {}) {
  return {success: true, data: {
    // Full settings responses intentionally conflict with every editable draft.
    panel_title: 'Server title', hostname: 'server-host', username: 'server-admin', basic_auth_user: 'server-basic',
    github_proxy: 'https://server.example', timezone: 'UTC',
    panel_auto_update: {panel_auto_update_enabled: 'false', panel_auto_update_mode: 'patch_only'},
    server_time: 1800000100000, ntp_synced: true, ntp_enabled: true, ntp_service: 'chronyd', ...overrides
  }};
}
function readRequest(request) {
  assert(request, 'A successful NTP write must issue an immediate status read.');
  assert.equal(request.url, '/settings');
  assert.equal(request.options.method || 'GET', 'GET');
  assert.equal(request.options.timeout, 15000);
  assert.equal(request.options.body, undefined, 'Status refreshes must never write drafts.');
}
async function completeImmediate(h, status = reply()) {
  const operation = h.page.syncNTP();
  h.requests.at(-1).resolve({success: true});
  await flush();
  readRequest(h.requests.at(-1));
  h.requests.at(-1).resolve(status);
  await operation;
}

(async () => {
  {
    const h = harness(), p = h.page;
    seedDrafts(p);
    const expected = drafts(p);
    const operation = p.syncNTP();
    assert.equal(h.requests.length, 1);
    assert.equal(h.requests[0].url, '/settings');
    assert.equal(h.requests[0].options.method, 'PUT');
    assert.deepEqual(copy(h.requests[0].options.body), {ntp_sync: true}, 'NTP writes may contain only the synchronization command.');
    assert.equal(p.ntpSyncing, true);
    assert.equal(h.disabled(syncExpression), true);
    controlsEnabled(h);
    await p.syncNTP();
    assert.equal(h.requests.length, 1, 'Repeated clicks during the write must not submit duplicate commands.');
    h.requests[0].resolve({success: true});
    await flush();
    readRequest(h.requests[1]);
    assert.equal(p.ntpSyncing, true, 'The NTP button stays busy until the immediate status read settles.');
    controlsEnabled(h);
    assert.deepEqual(drafts(p), expected, 'A deferred status read must not clear the verified-account state or any draft.');
    await p.syncNTP();
    assert.equal(h.requests.length, 2, 'Repeated clicks during the read must not submit duplicate commands.');
    seedDrafts(p, 'while-reading');
    const edited = drafts(p);
    h.requests[1].resolve(reply());
    await operation;
    assert.deepEqual(drafts(p), edited, 'The full settings response must not replace edits made while the status read was pending.');
    assert.equal(p.serverTimeBase, reply().data.server_time);
    assert.equal(p.serverTimeFetchedAt, h.now());
    assert(p.serverTime, 'The displayed clock should be refreshed.');
    assert.equal(p.ntpSynced, true);
    assert.equal(p.ntpEnabled, true);
    assert.equal(p.ntpService, 'chronyd');
    assert.equal(p.ntpSyncing, false);
    assert.equal(h.disabled(syncExpression), false);
    controlsEnabled(h);
    assert.equal(h.timers.size, 0, 'An already synchronized clock needs no follow-up.');
    assert.equal(h.intervals.size, 0, 'NTP synchronization must not create a background polling interval.');
  }

  {
    const h = harness(), p = h.page;
    seedDrafts(p);
    await completeImmediate(h, reply({ntp_synced: false}));
    assert.equal(h.timers.size, 1, 'An unsynchronized clock gets exactly one follow-up.');
    assert.equal(h.advance(4999).length, 0);
    assert.equal(h.requests.length, 2);
    seedDrafts(p, 'after-immediate-read');
    const [followup] = h.advance(1);
    assert.equal(h.requests.length, 3);
    readRequest(h.requests[2]);
    controlsEnabled(h);
    p.hostname = 'edited-during-followup';
    const edited = drafts(p);
    h.requests[2].resolve(reply({server_time: 1800000200000, ntp_synced: false, ntp_service: 'systemd-timesyncd'}));
    await followup;
    assert.deepEqual(drafts(p), edited, 'The delayed read must preserve drafts changed after the immediate read.');
    assert.equal(p.serverTimeBase, 1800000200000);
    assert.equal(p.ntpService, 'systemd-timesyncd');
    assert.equal(p.ntpSynced, false);
    assert.equal(h.timers.size, 0);
    h.advance(60000);
    assert.equal(h.requests.length, 3, 'An unsynchronized follow-up must not turn into continuous polling.');
    assert.equal(h.requests.filter(request => request.options.method === 'PUT').length, 1);
    assert.equal(h.intervals.size, 0);
  }

  for (const failure of [{success: false, message: 'write failed'}, new Error('write unavailable')]) {
    const h = harness(), p = h.page;
    seedDrafts(p);
    const expected = drafts(p), beforeTime = timeState(p), operation = p.syncNTP();
    if (failure instanceof Error) h.requests[0].reject(failure); else h.requests[0].resolve(failure);
    await operation;
    assert.equal(h.requests.length, 1, 'A failed write must never launch a status read.');
    assert.deepEqual(drafts(p), expected);
    assert.deepEqual(timeState(p), beforeTime);
    assert.equal(p.ntpSyncing, false);
    assert.equal(h.timers.size, 0);
    assert.equal(h.notices.at(-1)?.type, 'error');
    controlsEnabled(h);
  }

  const invalidReads = [
    new Error('read unavailable'), {success: false, message: 'read failed'}, {success: true},
    reply({server_time: undefined}), reply({server_time: 0}), reply({server_time: -1}),
    reply({server_time: NaN}), reply({server_time: Infinity}), reply({server_time: '1800000100000'}),
    reply({ntp_synced: 'false'}), reply({ntp_enabled: 1}), reply({ntp_service: null})
  ];
  for (const response of invalidReads) {
    const h = harness(), p = h.page;
    seedDrafts(p);
    Object.assign(p, {serverTimeBase: 1790000000000, serverTimeFetchedAt: h.now() - 100, serverTime: 'existing clock', ntpSynced: false, ntpEnabled: false, ntpService: 'existing service'});
    const expected = drafts(p), beforeTime = timeState(p), operation = p.syncNTP();
    h.requests[0].resolve({success: true});
    await flush();
    if (response instanceof Error) h.requests[1].reject(response); else h.requests[1].resolve(response);
    await operation;
    assert.deepEqual(drafts(p), expected, 'Failed or malformed time reads must leave all drafts and account state unchanged.');
    assert.deepEqual(timeState(p), beforeTime, 'Malformed responses must not partially update clock or NTP status.');
    assert.equal(p.ntpSyncing, false);
    assert.equal(h.timers.size, 0, 'A failed immediate read must not schedule a follow-up.');
    assert.equal(h.notices.at(-1)?.type, 'error');
    controlsEnabled(h);
  }

  for (const response of [new Error('follow-up unavailable'), reply({ntp_enabled: 'true'})]) {
    const h = harness(), p = h.page;
    seedDrafts(p);
    await completeImmediate(h, reply({ntp_synced: false}));
    const [followup] = h.advance(5000), expected = drafts(p), beforeTime = timeState(p);
    if (response instanceof Error) h.requests[2].reject(response); else h.requests[2].resolve(response);
    await assert.doesNotReject(followup, 'A delayed read failure must be handled by its timer callback.');
    assert.deepEqual(drafts(p), expected);
    assert.deepEqual(timeState(p), beforeTime);
    assert.equal(h.notices.at(-1)?.type, 'error');
    assert.equal(h.timers.size, 0);
  }

  {
    const h = harness(), p = h.page;
    seedDrafts(p);
    await completeImmediate(h, reply({ntp_synced: false}));
    const second = p.syncNTP();
    assert.equal(h.timers.size, 0, 'A new synchronization replaces the previous delayed follow-up.');
    h.advance(5000);
    assert.equal(h.requests.length, 3, 'An obsolete timer must not issue a read during a newer write.');
    h.requests[2].resolve({success: true});
    await flush();
    h.requests[3].resolve(reply({ntp_synced: false}));
    await second;
    assert.equal(h.timers.size, 1, 'Repeated operations must leave only the newest follow-up.');
    p.destroy();
    assert.equal(h.timers.size, 0, 'Leaving the component cancels its delayed follow-up.');
    h.advance(60000);
    await p.syncNTP();
    assert.equal(h.requests.length, 4, 'A destroyed component must not issue timer or user-triggered requests.');
  }

  {
    const h = harness(), p = h.page;
    seedDrafts(p);
    await completeImmediate(h, reply({ntp_synced: false}));
    const [oldFollowup] = h.advance(5000), oldRead = h.requests[2];
    readRequest(oldRead);
    const newer = p.syncNTP();
    assert.equal(oldRead.options.signal.aborted, true, 'A newer operation should cancel the obsolete read.');
    h.requests[3].resolve({success: true});
    await flush();
    assert.equal(p.ntpSyncing, true);
    h.requests[4].resolve(reply({server_time: 1800000300000, ntp_service: 'newest service'}));
    await newer;
    const latest = timeState(p), expected = drafts(p), noticeCount = h.notices.length;
    oldRead.resolve(reply({server_time: 1790000000000, ntp_synced: false, ntp_service: 'stale service'}));
    await oldFollowup;
    assert.deepEqual(timeState(p), latest, 'A late response from a canceled read must not overwrite newer clock status.');
    assert.deepEqual(drafts(p), expected);
    assert.equal(h.notices.length, noticeCount);
    assert.equal(h.timers.size, 0);
    assert.equal(h.intervals.size, 0);
  }

  for (const phase of ['write', 'immediate read', 'follow-up read']) {
    const h = harness(), p = h.page;
    seedDrafts(p);
    let operation;
    if (phase === 'follow-up read') {
      await completeImmediate(h, reply({ntp_synced: false}));
      [operation] = h.advance(5000);
    } else {
      operation = p.syncNTP();
      if (phase === 'immediate read') { h.requests[0].resolve({success: true}); await flush(); }
    }
    const pending = h.requests.at(-1), requestCount = h.requests.length;
    const expected = drafts(p), beforeTime = timeState(p), noticeCount = h.notices.length;
    p.destroy();
    if (phase !== 'write') assert.equal(pending.options.signal.aborted, true);
    pending.resolve(phase === 'write' ? {success: true} : reply({server_time: 1800000400000}));
    await operation;
    assert.deepEqual(drafts(p), expected, 'Responses arriving after destruction must not touch drafts.');
    assert.deepEqual(timeState(p), beforeTime, 'Responses arriving after destruction must not update clock state.');
    assert.equal(h.notices.length, noticeCount, 'Disposed components must not show completion notices.');
    assert.equal(p.ntpSyncing, false);
    assert.equal(h.timers.size, 0);
    h.advance(60000);
    assert.equal(h.requests.length, requestCount, 'Leaving during a request must not create subsequent reads.');
  }

  {
    const h = harness();
    await h.page.syncNTP();
    assert.equal(h.requests.length, 0, 'Unverified settings must still block NTP writes.');
  }
  console.log('PASS settings NTP: controls and drafts survive deferred reads; writes deduplicate; one follow-up; failures, stale responses, and component teardown stay isolated');
})().catch(error => { console.error(error); process.exit(1); });
