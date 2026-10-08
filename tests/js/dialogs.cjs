const fs = require('fs');
const path = require('path');
const vm = require('vm');
const assert = require('assert');

let document;
class Element {
    constructor(tag) { this.tagName = tag; this.children = []; this.attributes = {}; this.events = {}; this.style = {}; this.isConnected = false; }
    setAttribute(key, value) { this.attributes[key] = value; }
    appendChild(child) { child.parent = this; child.isConnected = true; this.children.push(child); return child; }
    addEventListener(name, handler) { (this.events[name] ||= []).push(handler); }
    emit(name, properties = {}) {
        const event = { target: this, preventDefault() { this.defaultPrevented = true; }, ...properties };
        for (const handler of this.events[name] || []) handler(event);
        return event;
    }
    focus() { document.activeElement = this; }
    remove() { this.isConnected = false; this.parent.children = this.parent.children.filter(item => item !== this); }
    getBoundingClientRect() { return { left: 10, top: 10, right: 200, bottom: 200 }; }
}
class Dialog extends Element {
    showModal() { this.open = true; this.openedModally = true; }
    close() { this.open = false; this.emit('close'); }
}
document = {
    body: new Element('body'),
    createElement: tag => tag === 'dialog' ? new Dialog(tag) : new Element(tag),
    addEventListener() {},
};
const trigger = document.body.appendChild(new Element('button'));
trigger.focus();
const nativeCalls = [];
const context = {
    document, console, setTimeout: () => 1,
    window: { confirm: message => { nativeCalls.push(message); return true; }, alert: message => nativeCalls.push(message) },
};
vm.createContext(context);
vm.runInContext(fs.readFileSync(path.join(__dirname, '../../web/js/app.js'), 'utf8'), context);
const currentDialog = () => document.body.children.find(element => element.tagName === 'dialog');
const buttons = dialog => dialog.children[0].children[1].children;

(async () => {
    const cancelled = context.confirmModal('<strong>Do not execute this markup</strong>');
    let dialog = currentDialog();
    assert(dialog.openedModally, 'must use modal presentation so the browser makes the background inert');
    assert.equal(document.activeElement, buttons(dialog)[0], 'cancel receives initial focus');
    assert.equal(dialog.children[0].children[0].textContent, '<strong>Do not execute this markup</strong>');
    assert.equal(dialog.attributes['aria-labelledby'], dialog.children[0].children[0].id);
    assert(dialog.emit('cancel').defaultPrevented);
    assert.equal(await cancelled, false);
    assert.equal(document.activeElement, trigger);
    assert.equal(currentDialog(), undefined);

    const confirmed = context.confirmModal('Delete');
    dialog = currentDialog();
    buttons(dialog)[1].emit('click');
    assert.equal(await confirmed, true);
    assert.equal(document.activeElement, trigger);

    const backdrop = context.confirmModal('Cancel via backdrop');
    currentDialog().emit('click', { clientX: 0, clientY: 0 });
    assert.equal(await backdrop, false);

    const alert = context.alertModal('Long error');
    dialog = currentDialog();
    assert.equal(buttons(dialog).length, 1);
    buttons(dialog)[0].emit('click');
    assert.equal(await alert, undefined);
    assert.equal(document.activeElement, trigger);

    context.showToast('Saved', 'success');
    assert.equal(document.body.children.at(-1).attributes.role, 'status');
    context.showToast('Failed', 'error');
    assert.equal(document.body.children.at(-1).attributes.role, 'alert');

    document.createElement = tag => new Element(tag);
    assert.equal(await context.confirmModal('Legacy confirm'), true);
    assert.equal(await context.alertModal('Legacy alert'), undefined);
    assert.deepStrictEqual(nativeCalls, ['Legacy confirm', 'Legacy alert']);
    console.log('Dialogs preserve confirmation results, cancel/focus behavior, safe text, and accessible notifications.');
})().catch(error => { console.error(error); process.exitCode = 1; });
