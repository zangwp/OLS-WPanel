const fs = require('node:fs'), vm = require('node:vm'), assert = require('node:assert/strict'), path = require('node:path');
const source = fs.readFileSync(path.join(__dirname, '../../web/templates/vps.html'), 'utf8');
const script = [...source.matchAll(/<script[^>]*>([\s\S]*?)<\/script>/g)][0][1].replace(/{{[\s\S]*?}}/g, 'translated');
let calls = [], response;
const context = {formatBytes: n => `${n} bytes`, api: async (url, options) => {
  calls.push({url, options}); return typeof response === 'function' ? response() : response;
}};
vm.createContext(context); vm.runInContext(script, context);
(async () => {
  const page = context.vpsPage();
  assert.equal(page.bytes(undefined), '--'); assert.equal(page.bytes(0), '0 bytes');
  response = {success:true,data:{identity:{addresses:['2001:db8::1','192.0.2.1','192.0.2.1',null]},dns:{current:['1.1.1.1','2606:4700:4700::1111']}}};
  await page.load();
  assert.deepEqual(Array.from(page.addresses(4)), ['192.0.2.1']);
  assert.deepEqual(Array.from(page.addresses(6)), ['2001:db8::1']);
  assert.deepEqual(Array.from(page.dnsAddresses(4)), ['1.1.1.1']);
  assert.deepEqual(Array.from(page.dnsAddresses(6)), ['2606:4700:4700::1111']);
  const previous = page.overview;
  response = () => {throw Error('offline');}; await page.load();
  assert.equal(page.overview, previous); assert.equal(page.error, 'offline'); assert.equal(page.loading, false);
  let release; response = () => new Promise(resolve => {release = resolve;});
  const pending = page.load(); await page.load();
  assert.equal(calls.length, 3, 'refreshes must not overlap');
  release({success:true,data:{identity:{addresses:[]}}}); await pending;
  assert.deepEqual(Array.from(page.addresses(4)), []); assert.deepEqual(Array.from(page.addresses(6)), []);
  assert(calls.every(call => call.url === '/vps/overview' && !call.options), 'server page only issues read requests');
  for (const forbidden of ['applyDNS','testDNS','saveCustomSwap','removeManagedSwap',"tab='maintenance'",'resource_snapshot']) assert(!source.includes(forbidden));
  console.log('PASS read-only server page: separate address families, missing versus zero values, safe refresh and no mutation requests');
})().catch(error => {console.error(error); process.exitCode = 1;});
