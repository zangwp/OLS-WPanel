const fs = require('fs'), path = require('path'), vm = require('vm'), assert = require('assert');
function load(file) {
  const source = [...fs.readFileSync(path.resolve(__dirname, '../../web/templates/' + file), 'utf8').matchAll(/<script[^>]*>([\s\S]*?)<\/script>/g)].map(x => x[1]).join('\n');
  const ctx = { t: key => key, showToast() {}, window: {}, document: {}, api: async () => { throw Error('offline'); } };
  vm.createContext(ctx); vm.runInContext(source, ctx); return ctx;
}
function deferred() { let resolve; const promise = new Promise(r => resolve = r); return { promise, resolve }; }
(async () => {
  const db = load('database_detail.html'), model = db.databaseDetail(); model.site = {id: 1};
  let writes = 0;
  db.api = async (url, opts) => { if (opts) writes++; throw Error('offline'); };
  await model.saveBackupSettings(); await model.fetchBackupSettings(); await model.saveBackupSettings();
  assert.equal(writes, 0); assert(!model.backupSettingsLoaded); assert(model.backupSettingsError);
  db.api = async () => ({success: true, data: {enabled: true}});
  await model.fetchBackupSettings(); assert(!model.backupSettingsLoaded);
  db.api = async () => ({success: true, data: {enabled: true, keep_count: 9}});
  await model.fetchBackupSettings(); assert(model.backupSettingsLoaded); assert.equal(model.backupKeepCount, 9);
  const first = deferred(), sent = []; let active = 0, maxActive = 0;
  db.api = async (url, opts) => { sent.push({...opts.body}); maxActive = Math.max(maxActive, ++active); if(sent.length === 1) await first.promise; active--; return {success: true}; };
  model.backupEnabled = false; const saving = model.saveBackupSettings();
  model.backupKeepCount = 12; await model.saveBackupSettings(); assert.equal(sent.length, 1);
  first.resolve(); await saving; assert.equal(sent.length, 2); assert.equal(sent[1].keep_count, 12); assert.equal(maxActive, 1); assert(!model.backupSettingsSaving);
  db.api = async () => ({success: false, message: 'not saved'});
  await model.saveBackupSettings(); assert(!model.backupSettingsLoaded); assert.equal(model.backupSettingsError, 'not saved');

  const cron = load('cron.html'), manager = cron.cronManager(), pending = deferred(), calls = [];
  cron.api = async (url, opts) => { calls.push({url, opts}); return opts ? pending.promise : {success: true, data: []}; };
  manager.openCreate(); manager.form.name = 'original'; const submit = manager.saveJob();
  await manager.saveJob(); assert.equal(calls.length, 1); assert(manager.saving);
  manager.showModal = false; manager.openEdit({id: 5, name: 'new editor', cron_expression: '0 2 * * *'});
  pending.resolve({success: true}); await submit;
  assert(manager.showModal); assert.equal(manager.form.name, 'new editor'); assert.equal(manager.editingId, 5); assert(!manager.saving);
  assert.equal(calls[0].url, '/cron'); assert.equal(calls[0].opts.body.name, 'original');
  cron.api = async () => { throw Error('failed'); };
  await manager.saveJob(); assert(!manager.saving); assert.equal(manager.form.name, 'new editor');
  console.log('PASS backup/cron: failed and malformed loads block writes, latest policy saves serially, duplicate task submission and stale form reset prevented');
})().catch(error => {console.error(error); process.exit(1);});
