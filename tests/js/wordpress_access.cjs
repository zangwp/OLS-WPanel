const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const {test} = require('node:test');
const html=fs.readFileSync(path.join(__dirname,'../../web/templates/wordpress_access.html'),'utf8');
const source=html.match(/<script>([\s\S]*?)<\/script>/)[1];
function setup() {
    const calls=[],forms=[],fields=[],watchers=new Map(),observations=[],popup={opener:{},closed:false,close(){this.closed=true;}};
    const context={URL,Date,AbortController,crypto:require('node:crypto').webcrypto,t:key=>key,showToast(){},navigator:{clipboard:{async writeText(){}}},window:{open:()=>popup},document:{body:{append:form=>forms.push(form)},createElement:type=>type==='form'?{style:{},append:field=>fields.push(field),submit(){this.submitted=true;},remove(){this.removed=true;}}:{}}};
    popup.document=context.document;popup.document.head={append(){}};
    context.api=async(url,options)=>{calls.push({url,options});return {success:true,data:{}};};
    vm.createContext(context);vm.runInContext(source,context);
    const component=context.wordpressPanelAccess();component.site={id:1,domain:'site.example',ssl_enabled:true,site_type:'wordpress'};
    component.detailTab='overview';component.$watch=(key,callback)=>{assert(!watchers.has(key),'duplicate watcher');watchers.set(key,callback);};
    component.$dispatch=(name,detail)=>observations.push({name,detail});
    component.status={installed:true,sso_enabled:true,sso_available:true,administrators:[{id:7}],installation_path:'/'};
    component.password='panel-password';component.code='123456';component.administratorID='7';
    return {component,context,calls,forms,fields,popup,watchers,observations};
}
const deferred=()=>{let resolve,reject;const promise=new Promise((a,b)=>{resolve=a;reject=b;});return {promise,resolve,reject};};
const settle=async()=>{for(let i=0;i<3;i++)await new Promise(resolve=>setImmediate(resolve));};
const readStatus=(extra={})=>({success:true,data:{installed:true,sso_enabled:true,sso_available:true,administrators:[{id:7}],manual_login_url:'https://site.example/private/',login_suffix:'private',installation_path:'/',...extra}});
test('login links reject cross-origin schemes, credentials and fragments',()=>{
    const {component}=setup();
    assert.equal(component.safeAddress('https://site.example/private-login/'),'https://site.example/private-login/');
    for(const value of ['javascript:alert(1)','https://other.example/','http://site.example/','https://admin@site.example/','https://site.example/#token','https://site.example.evil/']) assert.equal(component.safeAddress(value),'');
});
test('successful authorization submits the secret only in a removed POST form and clears credentials',async()=>{
    const {component,context,calls,forms,fields,popup}=setup();
    context.api=async(url,options)=>{calls.push({url,options});return {success:true,data:{action_url:'https://site.example/index.php',token:'A'.repeat(43),generation:'b'.repeat(32),expires_at:new Date(Date.now()+60000).toISOString()}};};
    await component.login();
    assert.equal(calls.length,1);assert.equal(calls[0].options.allowAuthFailure,true);assert.equal(calls[0].options.body.confirm,true);
    assert.equal(forms[0].method,'POST');assert.equal(forms[0].action,'https://site.example/index.php');assert.equal(forms[0].target,'_self');assert(forms[0].submitted);assert(forms[0].removed);
    assert.equal(fields[0].name,'ols_wpanel_access_token');assert.equal(fields[1].name,'ols_wpanel_access_generation');
    assert.equal(popup.opener,null);assert.equal(component.password,'');assert.equal(component.code,'');assert.equal(component.busy,false);
});
test('expired, foreign or malformed authorization responses close the popup and revoke tickets',async()=>{
    for(const change of [{action_url:'https://other.example/index.php'},{expires_at:new Date(Date.now()-1000).toISOString()},{generation:'invalid'},{token:'short'}]){
        const {component,context,calls,forms,popup}=setup();
        context.api=async(url,options)=>{calls.push({url,options});return {success:true,data:{action_url:'https://site.example/index.php',token:'A'.repeat(43),generation:'b'.repeat(32),expires_at:new Date(Date.now()+60000).toISOString(),...change}};};
        await component.login();assert.equal(forms.length,0);assert(popup.closed);assert(calls.at(-1).url.endsWith('/revoke'));assert(component.error);assert.equal(component.password,'');
    }
});
test('popup denial, disabled SSO and repeated clicks do not issue tickets',async()=>{
    const {component,context,calls}=setup();
    component.status.sso_enabled=false;await component.login();assert.equal(calls.length,0);
    component.status.sso_enabled=true;context.window.open=()=>null;await component.login();assert.equal(calls.length,0);
    component.busy=true;await component.login();assert.equal(calls.length,0);
});
test('suffix settings explicitly clear a legacy manual override only when the user saves',async()=>{
    const {component,context,calls}=setup();
    assert(!html.includes('x-model="manualURL"'));assert(!html.includes('type="url"'));assert.equal(Object.hasOwn(component,'manualURL'),false);
    context.api=async(url,options)=>{calls.push({url,options});return readStatus({manual_login_url:'https://site.example/legacy/',login_url:'https://site.example/legacy/',login_suffix:''});};
    await component.load();assert.equal(component.status.manual_login_url,'https://site.example/legacy/');assert(calls.every(call=>!call.options?.method));
    calls.length=0;component.settingsPassword='password';component.settingsCode='654321';component.suffix='new-login';component.enableSSO=false;
    await component.save();assert.equal(calls[0].options.method,'PUT');assert.equal(calls[0].options.body.manual_login_url,'');assert.equal(calls[0].options.body.login_suffix,'new-login');assert.equal(calls[0].options.body.sso_enabled,false);assert.equal(calls[0].options.body.current_password,'password');assert.equal(calls[0].options.body.code,'654321');assert.equal(calls[0].options.body.confirm,true);assert.equal(component.settingsPassword,'');assert.equal(component.settingsCode,'');
});
test('failed status refresh removes stale authorization capabilities',async()=>{
    const {component,context}=setup();context.api=async()=>{throw new Error('unavailable');};await component.load();assert.equal(component.status,null);assert.equal(component.loading,false);assert.equal(component.error,'unavailable');
});

test('file lock blocks access-setting mutations while leaving pending-ticket revocation available',async()=>{
    const {component,calls}=setup();component.site.file_lock_enabled=true;component.settingsPassword='password';
    await component.save();assert.equal(calls.length,0);
    await component.revoke();assert.equal(calls.length,1);assert(calls[0].url.endsWith('/revoke'));
});

test('access uses its automatic init once, watches navigation once and shares the pending read',async()=>{
    assert.match(html, /x-data="wordpressPanelAccess\(\)"/);
    assert(!/x-data="wordpressPanelAccess\(\)"[^>]*x-init=/.test(html));
    const {component,context,calls,watchers}=setup();const pending=deferred();component.status=null;
    context.api=(url,options)=>{calls.push({url,options});return pending.promise;};
    component.init();await component.load();assert.equal(watchers.size,1);assert.equal(calls.length,1);
    assert.equal(calls[0].options.signal.aborted,false);assert.equal(calls[0].options.cache,'no-store');
    pending.resolve(readStatus());await settle();assert.equal(component.status.installed,true);assert.equal(component.loading,false);
});

test('hidden and PHP access cards perform no WordPress status read',async()=>{
    for(const tab of ['cache','security','logs']){
        const {component,calls}=setup();component.detailTab=tab;component.init();await component.load();assert.equal(calls.length,0);
    }
    const {component,calls}=setup();component.site.site_type='php';component.init();await component.load();assert.equal(calls.length,0);
});

test('leaving overview aborts reads and clears credentials before a late response arrives',async()=>{
    const {component,context,calls,watchers}=setup();const pending=deferred();component.status=null;component.settingsPassword='settings-secret';component.settingsCode='654321';component.loginOpen=true;
    context.api=(url,options)=>{calls.push({url,options});return pending.promise;};component.init();
    component.detailTab='security';watchers.get('detailTab')('security');
    assert.equal(calls[0].options.signal.aborted,true);assert.equal(component.loading,false);assert.equal(component.readController,null);assert.equal(component.loginOpen,false);
    assert.equal(component.password,'');assert.equal(component.code,'');assert.equal(component.settingsPassword,'');assert.equal(component.settingsCode,'');
    pending.resolve(readStatus({manual_login_url:'https://site.example/stale/',login_suffix:'stale',administrators:[{id:88}]}));await settle();
    assert.equal(component.status,null);assert.equal(Object.hasOwn(component,'manualURL'),false);assert.equal(component.suffix,'');assert.equal(component.enableSSO,false);assert.equal(component.administratorID,'7');assert.equal(component.error,'');
});

test('access shares only a sanitized public address with its parent and clears a failed observation',async()=>{
    const {component,context,observations}=setup();context.api=async()=>readStatus({login_url:'https://site.example/plugin-login/',password:'must-not-dispatch',token:'must-not-dispatch'});
    await component.load();assert.equal(observations.length,1);assert.equal(observations[0].name,'wordpress-access-observed');
    assert.equal(observations[0].detail.login_url,'https://site.example/plugin-login/');assert.deepEqual(Object.keys(observations[0].detail).sort(),['install_url','installed','login_url','site_id']);
    context.api=async()=>{throw new Error('offline');};await component.load();assert.equal(observations.at(-1).detail.login_url,'');assert.equal(observations.at(-1).detail.installed,undefined);
});

test('advanced authorization remains inside settings and closing settings removes both proofs',()=>{
    const {component}=setup();const detailsStart=html.indexOf('<details class="wp-access-settings');const detailsEnd=html.indexOf('</details>',detailsStart);
    const advancedButton=html.indexOf('@click="loginOpen = !loginOpen"');assert(advancedButton>detailsStart&&advancedButton<detailsEnd);
    assert.equal(html.includes("status.installed ? t('wp_access.open_login') : t('wp_access.open_install')"),false);
    const toggle=html.match(/<details[^>]*@toggle="([^"]+)"/)[1];
    component.settingsOpen=true;component.settingsPassword='secret';component.settingsCode='123456';component.loginOpen=true;
    vm.runInNewContext('with (data) { '+toggle+' }',{data:component,$el:{open:false}});
    assert.equal(component.password,'');assert.equal(component.code,'');assert.equal(component.settingsPassword,'');assert.equal(component.settingsCode,'');assert.equal(component.loginOpen,false);
});

test('returning to overview after cancellation starts a new read and an older response cannot finish it',async()=>{
    const {component,context,calls,watchers}=setup();const old=deferred(),current=deferred();component.status=null;
    context.api=(url,options)=>{calls.push({url,options});return calls.length===1?old.promise:current.promise;};component.init();
    component.detailTab='cache';watchers.get('detailTab')('cache');component.detailTab='overview';watchers.get('detailTab')('overview');
    assert.equal(calls.length,2);assert.equal(calls[0].options.signal.aborted,true);assert.equal(calls[1].options.signal.aborted,false);assert.equal(component.loading,true);
    old.resolve(readStatus({login_suffix:'stale'}));await settle();assert.equal(component.status,null);assert.equal(component.loading,true);assert.equal(component.readController.signal,calls[1].options.signal);
    current.resolve(readStatus({login_suffix:'fresh'}));await settle();assert.equal(component.status.login_suffix,'fresh');assert.equal(component.suffix,'fresh');assert.equal(component.loading,false);
});

test('an aborted older read cannot display its failure over a newer successful observation',async()=>{
    const {component,context,calls}=setup();const old=deferred();component.status=null;
    context.api=(url,options)=>{calls.push({url,options});return calls.length===1?old.promise:Promise.resolve(readStatus());};
    const first=component.load();component.cancelRead();await component.load();old.reject(new Error('late abort'));await first;
    assert.equal(component.status.installed,true);assert.equal(component.error,'');assert.equal(component.loading,false);assert.equal(component.readController,null);
});

test('destroy aborts an in-flight read, clears all secrets and refuses late capabilities',async()=>{
    const {component,context,calls}=setup();const pending=deferred();component.status=null;component.settingsPassword='settings-secret';component.settingsCode='654321';
    context.api=(url,options)=>{calls.push({url,options});return pending.promise;};const first=component.load();component.destroy();
    assert.equal(calls[0].options.signal.aborted,true);assert.equal(component.password,'');assert.equal(component.code,'');assert.equal(component.settingsPassword,'');assert.equal(component.settingsCode,'');
    pending.resolve(readStatus());await first;assert.equal(component.status,null);assert.equal(component.loading,false);assert.equal(component.readController,null);
});
