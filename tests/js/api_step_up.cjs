const fs = require('fs'), vm = require('vm'), assert = require('assert'), path = require('path');
const script = fs.readFileSync(path.resolve(__dirname, '../../web/js/app.js'), 'utf8');
const start = script.indexOf('function api('), end = script.indexOf('const __apiGetCache', start);
let response, request;
const ctx = {t: key => key, document: {body: {dataset: {panelPrefix: '/panel'}}, querySelector: () => ({content: 'csrf'})}, window: {location: {href: ''}}, FormData, AbortController, setTimeout, clearTimeout, console: {error() {}}, friendlyAPIError: error => error.message, showToast() {}, fetch: async (url, options) => {request = options; return response;}};
vm.createContext(ctx); vm.runInContext(script.slice(start, end), ctx);
const reply = (status, data) => ({status, ok: status < 400, headers: {get: () => 'application/json'}, json: async () => data});
function cancellationHarness() {
  const timers = new Map(), seen = {request:null, cleared:0, toasts:[]};let sequence=0;
  const cancelContext={...ctx,window:{location:{href:''}},
    setTimeout:callback=>{const id=++sequence;timers.set(id,callback);return id;},
    clearTimeout:id=>{timers.delete(id);seen.cleared++;},
    showToast:(...args)=>seen.toasts.push(args),
    fetch:(url,options)=>{seen.request=options;return new Promise((resolve,reject)=>{
      const cancelled=()=>reject(Object.assign(new Error('AbortError'),{name:'AbortError'}));
      if(options.signal.aborted)cancelled();else options.signal.addEventListener('abort',cancelled,{once:true});
    })}
  };
  vm.createContext(cancelContext);vm.runInContext(script.slice(start,end),cancelContext);
  return {context:cancelContext,timers,seen};
}
function observedController() {
  const controller=new AbortController(), seen={added:0,removed:0};
  const add=controller.signal.addEventListener.bind(controller.signal),remove=controller.signal.removeEventListener.bind(controller.signal);
  controller.signal.addEventListener=(...args)=>{seen.added++;return add(...args);};
  controller.signal.removeEventListener=(...args)=>{seen.removed++;return remove(...args);};
  return {controller,seen};
}
(async () => {
  response = reply(401, {success: false, error_code: 'mfa_invalid_code', message: 'bad code'});
  await assert.rejects(ctx.api('/auth/mfa/disable', {allowAuthFailure: true, silent: true}), error => error.code === 'mfa_invalid_code' && error.status === 401);
  assert.equal(ctx.window.location.href, ''); assert(!Object.hasOwn(request, 'allowAuthFailure'));
  response = reply(401, {success: false, message: 'expired'});
  await assert.rejects(ctx.api('/auth/mfa/disable', {allowAuthFailure: true, silent: true}));
  assert.equal(ctx.window.location.href, '/panel/login');
  ctx.window.location.href = '';
  response = reply(401, {success: false, error_code: 'mfa_invalid_password', message: 'bad password'});
  await assert.rejects(ctx.api('/settings', {silent: true})); assert.equal(ctx.window.location.href, '/panel/login');
  ctx.window.location.href = '';
  await assert.rejects(ctx.api('/auth/login', {silent: true})); assert.equal(ctx.window.location.href, '');
  response = reply(503, {success: false, error_code: 'mfa_unavailable', message: 'unavailable'});
  await assert.rejects(ctx.api('/auth/mfa', {silent: true}), error => error.code === 'mfa_unavailable');
  const details = {address: '192.0.2.24', address_family: 'IPv4', http_status: 403};
  ctx.friendlyAPIError = () => 'Localized verification failure';
  for (const status of [400, 200]) {
    response = reply(status, {success: false, error_code: 'panel_domain_http_status', message: 'HTTP verification failed', details});
    await assert.rejects(ctx.api('/settings/panel-domain/check', {silent: true}), error => error.code === 'panel_domain_http_status' && error.details === details && error.message === 'Localized verification failure');
  }
  ctx.friendlyAPIError = error => error.message;
  {
    const {context,timers,seen}=cancellationHarness(),caller=observedController();
    const pending=context.api('/websites/1/wp-panel-access',{signal:caller.controller.signal,silent:true});
    assert.equal(seen.request.signal,caller.controller.signal,'without a timeout the fetch must receive the caller signal directly');
    caller.controller.abort();await assert.rejects(pending,error=>error.name==='AbortError');
    assert.equal(timers.size,0);assert.deepEqual(seen.toasts,[]);assert.equal(context.window.location.href,'');
  }
  {
    const {context,timers,seen}=cancellationHarness(),caller=observedController();
    const pending=context.api('/websites/1/wp-panel-access',{signal:caller.controller.signal,timeout:20000,silent:true});
    assert.notEqual(seen.request.signal,caller.controller.signal,'timeout and caller cancellation need one combined signal');
    const lateTimeout=[...timers.values()][0];caller.controller.abort();lateTimeout();
    await assert.rejects(pending,error=>error.name==='AbortError'&&error.message!=='common.request_timeout');
    assert.equal(seen.request.signal.aborted,true);assert.equal(timers.size,0);assert.equal(caller.seen.added,1);assert.equal(caller.seen.removed,1);
  }
  {
    const {context,timers,seen}=cancellationHarness(),caller=observedController();
    const pending=context.api('/websites/1/wp-panel-access',{signal:caller.controller.signal,timeout:20000,silent:true});
    [...timers.values()][0]();await assert.rejects(pending,error=>error.message==='common.request_timeout');
    assert.equal(seen.request.signal.aborted,true);assert.equal(caller.controller.signal.aborted,false,'API timeout must not cancel the caller controller');
    assert.equal(timers.size,0);assert.equal(caller.seen.removed,1);
  }
  {
    const {context,timers}=cancellationHarness(),caller=observedController();caller.controller.abort();
    await assert.rejects(context.api('/websites/1/wp-panel-access',{signal:caller.controller.signal,timeout:20000,silent:true}),error=>error.name==='AbortError');
    assert.equal(timers.size,0,'pre-cancelled requests must not start a timeout');assert.equal(caller.seen.added,0);
  }
  console.log('PASS API: step-up/session/typed errors preserved; external cancellation and timeouts combine and clean up without misclassifying cancelled navigation');
})().catch(error => {console.error(error); process.exit(1);});
