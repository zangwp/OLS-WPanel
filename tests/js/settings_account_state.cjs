const fs = require('fs'), vm = require('vm'), assert = require('assert'), path = require('path');
const source = [...fs.readFileSync(path.resolve(__dirname, '../../web/templates/settings.html'), 'utf8').matchAll(/<script[^>]*>([\s\S]*?)<\/script>/g)].map(x => x[1]).join('\n');
let calls = [], reply = {success: true, data: {username: 'admin', basic_auth_user: 'gateway'}}, fail = false;
const notices = [];
const ctx = {t: key => key, showToast(message, type) { notices.push({message, type}); }, setInterval: () => 1, clearInterval() {}, setTimeout() {}, window: {location: {hash: '', href: ''}}, api: async (url, options) => {calls.push({url, options}); if(fail) throw Error('failed'); return reply;}};
vm.createContext(ctx); vm.runInContext(source, ctx);
(async () => {
  const m = ctx.panelSettings();
  await m.saveBasicAuth(); await m.saveWebAccount(); assert.equal(calls.length, 0);
  await m.saveBasic(); await m.saveServerSetting('github_proxy',''); await m.saveAutoUpdate(); await m.testProxy(); assert.equal(calls.length,0,'Unread defaults cannot overwrite title, proxy, or automatic updates, or test an unverified proxy.');
  for (const data of [undefined, {}, {username:'admin'}]) {reply = {success:true, data}; await m.fetchSettings(); assert(!m.accountLoaded); assert(m.accountLoadError);}
  reply = {success:true, data:{username:'admin',basic_auth_user:'gateway'}}; await m.fetchSettings(); assert(m.accountLoaded);
  const beforeSettingsSave=calls.length; await m.saveAutoUpdate(); assert.equal(calls.length,beforeSettingsSave+1,'Verified settings remain editable.');
  m.pw.basicCurrent = 'current-test-password'; m.pw.basicCode = ' 123456 '; m.pw.basic = 'new-test-password';
  reply = {success:false,message:'not saved'}; await m.saveBasicAuth(); assert.equal(m.pw.basic,'new-test-password'); assert(!m.accountSaving);
  reply = {success:true}; await m.saveBasicAuth(); const request = calls.at(-1);
  assert.equal(request.options.body.old_password,'current-test-password'); assert.equal(request.options.body.code,'123456'); assert(request.options.allowAuthFailure); assert(request.options.silent, 'The form handles its own error feedback once.'); assert.equal(m.pw.basicCurrent,''); assert.equal(m.pw.basic,'');
  m.username = 'changed'; m.pw.old = 'current-test-password'; m.pw.code = 'recovery-test';
  fail = true; await m.saveWebAccount(); assert(!m.accountSaving); assert(!m.accountSaved); assert.equal(m.pw.old,'current-test-password');
  fail = false; await m.saveWebAccount(); assert(m.accountSaved); assert.equal(m.pw.old,''); assert.equal(m.pw.code,'');
  for (const kind of ['basic', 'web']) {
    const page = ctx.panelSettings(); page.accountLoaded = true;
    page.basicAuthUser = 'gateway-new'; page.pw.basicCurrent = 'current-test-password';
    page.username = 'renamed-admin'; page.originalUsername = 'admin'; page.pw.old = 'current-test-password';
    let finish, count = 0;
    ctx.api = () => { count++; return new Promise(resolve => { finish = resolve; }); };
    const operation = kind === 'basic' ? page.saveBasicAuth() : page.saveWebAccount();
    assert.equal(page.accountSaving, kind, 'Only the submitted form should display saving feedback.');
    const html = fs.readFileSync(path.resolve(__dirname, '../../web/templates/settings.html'), 'utf8');
    const labels = [...html.matchAll(/x-text="(accountSaving[^\"]+)"/g)].map(match => match[1]);
    const evaluate = expression => vm.runInNewContext('with (page) { '+expression+' }',{page,t:ctx.t});
    const values = labels.map(evaluate);
    assert.equal(values[kind === 'basic' ? 0 : 1], 'settings.saving');
    assert.equal(values[kind === 'basic' ? 1 : 0], 'settings.save_' + (kind === 'basic' ? 'web_account' : 'basic_auth'));
    const disabled = [...html.matchAll(/:disabled="(accountSaving[^\"]+)"/g)].map(match => match[1]);
    const busy = [...html.matchAll(/:aria-busy="(accountSaving[^\"]+)"/g)].map(match => match[1]);
    for (const attributes of [disabled, busy]) {
      assert.equal(attributes.length, 2);
      assert.equal(evaluate(attributes[kind === 'basic' ? 0 : 1]), true);
      assert.equal(evaluate(attributes[kind === 'basic' ? 1 : 0]), false, 'The untouched button stays enabled and does not announce saving.');
    }
    const beforeNotice = notices.length;
    await (kind === 'basic' ? page.saveWebAccount() : page.saveBasicAuth());
    assert.equal(count, 1, 'Overlapping credential changes must remain blocked.');
    assert.deepEqual(notices.slice(beforeNotice), [{message:'settings.account_change_in_progress',type:'info'}], 'A second save explains the pending operation instead of validating the other form.');
    finish({success:false,message:'retry'}); await operation;
    assert.equal(page.accountSaving, '', 'Failure must release both forms for an explicit retry.');
    assert(disabled.every(expression => evaluate(expression) === false));
    assert(busy.every(expression => evaluate(expression) === false));
    page.accountLoaded = false;
    assert(disabled.every(expression => evaluate(expression) === true), 'Unverified settings must still block both saves.');
  }
  console.log('PASS settings credentials: malformed load blocks saves, step-up credentials sent, failed save retains input, success clears sensitive fields');
})().catch(error => {console.error(error); process.exit(1);});
