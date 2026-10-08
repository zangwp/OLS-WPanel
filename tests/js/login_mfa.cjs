const fs = require('fs'), vm = require('vm'), assert = require('assert'), path = require('path');
const repo = path.resolve(__dirname, '../..');
const source = fs.readFileSync(path.join(repo, 'web/templates/login.html'), 'utf8');
const script = [...source.matchAll(/<script[^>]*>([\s\S]*?)<\/script>/g)].find(m => m[1].includes('function loginForm'))[1];
let calls = [], focus = 0, redirects = 0, response;
const context = {
  t: key => key, document: {body: {dataset: {panelPrefix: '/test'}}, querySelector: () => ({content: ''}), getElementById: () => ({focus() {focus++;}})},
  window: {location: {href: ''}}, setTimeout: () => {redirects++;}, requestAnimationFrame: fn => fn(),
  fetch: async () => ({ok: true, json: async () => ({success: true, data: {token: 'test-csrf'}})}),
  api: async (url, opts) => {calls.push(opts.body); return typeof response === 'function' ? response() : response;}
};
vm.createContext(context); vm.runInContext(script, context);
const form = context.loginForm();
form.$nextTick = fn => fn(); form.$refs = {codeInput: {focus() {focus++;}}};
(async () => {
  await form.login(); assert.equal(calls.length, 0);
  form.username = 'admin'; form.password = 'synthetic-password';
  response = {success: true, data: {mfa_required: true}};
  await form.login(); assert(form.mfaRequired); assert(!form.success); assert(!form.loading); assert.equal(redirects, 0); assert.equal(focus, 1);
  await form.login(); assert.equal(calls.length, 1, 'empty MFA proof cannot send');
  form.code = '123456'; response = {success: false, message: 'invalid proof'};
  await form.login(); assert(!form.success); assert(!form.loading); assert.equal(form.error, 'invalid proof');
  form.loading = true; await form.login(); assert.equal(calls.length, 2, 'duplicate submission blocked'); form.loading = false;
  form.recoveryMode = true; form.code = ' synthetic-recovery-code ';
  response = {success: true, data: {username: 'admin'}};
  await form.login(); assert(form.success); assert.equal(redirects, 1); assert.equal(calls[2].code, 'synthetic-recovery-code'); assert.equal(form.password, ''); assert.equal(form.code, '');
  form.resetMFA(); assert(!form.mfaRequired); assert(!form.recoveryMode); assert.equal(form.password, '');
  console.log('PASS login MFA: no premature session UI/redirect, empty proof, invalid proof recovery, duplicate guard, recovery code and secret cleanup');
})().catch(error => {console.error(error); process.exit(1);});
