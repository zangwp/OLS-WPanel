const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const { test } = require('node:test');

const components = [
    ['database_detail.html', 'databaseDetail'],
    ['wordpress_site_detail.html', 'wordpressSiteDetail'],
    ['ai_diagnostics.html', 'aiDiagnosticsPage'],
    ['log_analysis.html', 'logAnalysisPage'],
    ['settings.html', 'systemUpdate'],
    ['settings.html', 'dbBackup'],
];
for (const [file, factory] of components) {
    test(factory + ' uses only its automatic Alpine initialization hook', () => {
        const html = fs.readFileSync(path.join(__dirname, '../../web/templates', file), 'utf8');
        const opening = [...html.matchAll(/<[^>]+\bx-data="([^"]+)"[^>]*>/g)].find(match => match[1] === factory + '()');
        assert(opening, 'component disappeared'); assert(!/\bx-init=/.test(opening[0]), 'automatic init and directive would both run');
        const script = [...html.matchAll(/<script[^>]*>([\s\S]*?)<\/script>/g)].find(match => match[1].includes('function ' + factory + '()'))[1].replace(/{{[\s\S]*?}}/g, 'translated');
        const context = { console, t: key => key }; vm.createContext(context); vm.runInContext(script, context);
        assert.equal(typeof context[factory]().init, 'function', 'removing the directive requires an automatic init hook');
    });
}
