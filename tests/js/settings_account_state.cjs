const fs = require('fs'), vm = require('vm'), assert = require('assert'), path = require('path');
const source = [...fs.readFileSync(path.resolve(__dirname, '../../web/templates/settings.html'), 'utf8').matchAll(/<script[^>]*>([\s\S]*?)<\/script>/g)].map(x => x[1]).join('\n');
let calls = [], reply = {success: true, data: {username: 'admin', basic_auth_user: 'gateway'}}, fail = false;
const ctx = {t: key => key, showToast() {}, setInterval: () => 1, clearInterval() {}, setTimeout() {}, window: {location: {hash: '', href: ''}}, api: async (url, options) => {calls.push({url, options}); if(fail) throw Error('failed'); return reply;}};
vm.createContext(ctx); vm.runInContext(source, ctx);
(async () => {
  const m = ctx.panelSettings();
  await m.saveBasicAuth(); await m.saveWebAccount(); assert.equal(calls.length, 0);
  for (const data of [undefined, {}, {username:'admin'}]) {reply = {success:true, data}; await m.fetchSettings(); assert(!m.accountLoaded); assert(m.accountLoadError);}
  reply = {success:true, data:{username:'admin',basic_auth_user:'gateway'}}; await m.fetchSettings(); assert(m.accountLoaded);
  m.pw.basicCurrent = 'current-test-password'; m.pw.basicCode = ' 123456 '; m.pw.basic = 'new-test-password';
  reply = {success:false,message:'not saved'}; await m.saveBasicAuth(); assert.equal(m.pw.basic,'new-test-password'); assert(!m.accountSaving);
  reply = {success:true}; await m.saveBasicAuth(); const request = calls.at(-1);
  assert.equal(request.options.body.old_password,'current-test-password'); assert.equal(request.options.body.code,'123456'); assert(request.options.allowAuthFailure); assert.equal(m.pw.basicCurrent,''); assert.equal(m.pw.basic,'');
  m.username = 'changed'; m.pw.old = 'current-test-password'; m.pw.code = 'recovery-test';
  fail = true; await m.saveWebAccount(); assert(!m.accountSaving); assert(!m.accountSaved); assert.equal(m.pw.old,'current-test-password');
  fail = false; await m.saveWebAccount(); assert(m.accountSaved); assert.equal(m.pw.old,''); assert.equal(m.pw.code,'');
  console.log('PASS settings credentials: malformed load blocks saves, step-up credentials sent, failed save retains input, success clears sensitive fields');
})().catch(error => {console.error(error); process.exit(1);});
