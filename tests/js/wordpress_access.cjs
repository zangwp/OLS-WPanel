const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const {test} = require('node:test');
const html=fs.readFileSync(path.join(__dirname,'../../web/templates/wordpress_access.html'),'utf8');
const source=html.match(/<script>([\s\S]*?)<\/script>/)[1];
function setup() {
    const calls=[],forms=[],fields=[],watchers=new Map(),popup={opener:{},closed:false,close(){this.closed=true;}};
    const context={URL,Date,AbortController,crypto:require('node:crypto').webcrypto,t:key=>key,showToast(){},navigator:{clipboard:{async writeText(){}}},window:{open:()=>popup},document:{body:{append:form=>forms.push(form)},createElement:type=>type==='form'?{style:{},append:field=>fields.push(field),submit(){this.submitted=true;},remove(){this.removed=true;}}:{}}};
    popup.document=context.document;popup.document.head={append(){}};
    context.api=async(url,options)=>{calls.push({url,options});return {success:true,data:{}};};
    vm.createContext(context);vm.runInContext(source,context);
    const component=context.wordpressPanelAccess();component.site={id:1,domain:'site.example',ssl_enabled:true,site_type:'wordpress'};
    component.detailTab='overview';component.$watch=(key,callback)=>{assert(!watchers.has(key),'duplicate watcher');watchers.set(key,callback);};
    component.status={installed:true,sso_enabled:true,sso_available:true,administrators:[{id:7}],installation_path:'/'};
    component.administratorID='7';
    return {component,context,calls,forms,fields,popup,watchers};
}
const deferred=()=>{let resolve,reject;const promise=new Promise((a,b)=>{resolve=a;reject=b;});return {promise,resolve,reject};};
const settle=async()=>{for(let i=0;i<3;i++)await new Promise(resolve=>setImmediate(resolve));};
const readStatus=(extra={})=>({success:true,data:{installed:true,sso_enabled:true,sso_available:true,administrators:[{id:7}],manual_login_url:'https://site.example/private/',login_suffix:'private',installation_path:'/',...extra}});
test('login links reject cross-origin schemes, credentials and fragments',()=>{
    const {component}=setup();
    assert.equal(component.safeAddress('https://site.example/private-login/'),'https://site.example/private-login/');
    for(const value of ['javascript:alert(1)','https://other.example/','http://site.example/','https://admin@site.example/','https://site.example/#token','https://site.example.evil/','https://site.example/'+'x'.repeat(2048),null]) assert.equal(component.safeAddress(value),'');
});
test('successful authorization uses the panel session and submits a ticket only in a removed POST form',async()=>{
    const {component,context,calls,forms,fields,popup}=setup();
    context.api=async(url,options)=>{calls.push({url,options});return {success:true,data:{action_url:'https://site.example/index.php',token:'A'.repeat(43),generation:'b'.repeat(32),expires_at:new Date(Date.now()+60000).toISOString()}};};
    await component.login();
    assert.equal(calls.length,1);assert.equal(calls[0].options.method,'POST');assert.equal(Object.hasOwn(calls[0].options,'allowAuthFailure'),false);
    assert.deepEqual({...calls[0].options.body},{administrator_id:7,confirm:true});
    assert.equal(forms[0].method,'POST');assert.equal(forms[0].action,'https://site.example/index.php');assert.equal(forms[0].target,'_self');assert(forms[0].submitted);assert(forms[0].removed);
    assert.equal(fields[0].name,'ols_wpanel_access_token');assert.equal(fields[1].name,'ols_wpanel_access_generation');
    assert.equal(popup.opener,null);assert.equal(Object.hasOwn(component,'password'),false);assert.equal(Object.hasOwn(component,'code'),false);assert.equal(component.busy,false);
});
test('expired, foreign or malformed authorization responses close the popup and revoke tickets',async()=>{
    for(const change of [{action_url:'https://other.example/index.php'},{expires_at:new Date(Date.now()-1000).toISOString()},{generation:'invalid'},{token:'short'}]){
        const {component,context,calls,forms,popup}=setup();
        context.api=async(url,options)=>{calls.push({url,options});return {success:true,data:{action_url:'https://site.example/index.php',token:'A'.repeat(43),generation:'b'.repeat(32),expires_at:new Date(Date.now()+60000).toISOString(),...change}};};
        await component.login();assert.equal(forms.length,0);assert(popup.closed);assert(calls.at(-1).url.endsWith('/revoke'));assert(component.error);
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
    assert.equal(component.settingsPassword,'');assert.equal(component.settingsCode,'');
    pending.resolve(readStatus({manual_login_url:'https://site.example/stale/',login_suffix:'stale',administrators:[{id:88}]}));await settle();
    assert.equal(component.status,null);assert.equal(Object.hasOwn(component,'manualURL'),false);assert.equal(component.suffix,'');assert.equal(component.enableSSO,false);assert.equal(component.administratorID,'7');assert.equal(component.error,'');
});

test('ordinary address uses the detected plugin or installation address without publishing credentials elsewhere',async()=>{
    const {component,context}=setup();context.api=async()=>readStatus({login_url:'https://site.example/plugin-login/'});
    await component.load();assert.equal(component.safeAddress(component.status.login_url),'https://site.example/plugin-login/');
    context.api=async()=>readStatus({installed:false,sso_enabled:false,sso_available:false,administrators:[],install_url:'https://site.example/wp-admin/install.php'});
    await component.load();assert.equal(component.safeAddress(component.status.install_url),'https://site.example/wp-admin/install.php');assert.equal(component.canAuthorize(),false);assert.equal(component.canSetupAuthorization(),false);
    const addressLink=html.match(/<a[^>]*:href="safeAddress\(status\.installed[^>]*>/)[0];assert.match(addressLink,/target="_blank"/);assert.match(addressLink,/rel="noopener noreferrer"/);
});

test('single-administrator authorization opens its popup synchronously without a login form or panel proofs',async()=>{
    const {component,calls}=setup();component.loginOpen=false;component.settingsOpen=true;component.settingsPassword='settings-secret';component.settingsCode='654321';
    component.status.administrators=[{id:-1},{id:7},{id:'invalid'}];component.administratorID='';
    const pending=component.toggleAuthorization();
    assert.equal(component.loginOpen,false);assert.equal(component.settingsOpen,false);assert.equal(component.settingsPassword,'');assert.equal(component.settingsCode,'');assert.equal(component.administratorID,'7');assert.equal(calls.length,1);assert.equal(component.busy,true);
    assert.deepEqual({...calls[0].options.body},{administrator_id:7,confirm:true});await pending;
    const loginForm=html.match(/<form id="wp-access-login-form"[\s\S]*?<\/form>/)[0];
    assert(!/<input\b/.test(loginForm));assert(!html.includes('x-model="password"'));assert(!html.includes('x-model="code"'));assert.equal(Object.hasOwn(component,'password'),false);assert.equal(Object.hasOwn(component,'code'),false);
    assert(html.indexOf('id="wp-access-login-form"') < html.indexOf('<details id="wp-access-settings"'));
});

test('multiple administrators open an account picker without requests and authorize only the chosen account',async()=>{
    const {component,context,calls,forms}=setup();let opened=0;const popup=context.window.open();context.window.open=()=>{opened++;return popup;};component.status.administrators=[{id:7},{id:8}];component.administratorID='';component.settingsOpen=true;component.settingsPassword='settings-secret';component.settingsCode='654321';
    await component.toggleAuthorization();assert.equal(component.loginOpen,true);assert.equal(component.settingsOpen,false);assert.equal(component.settingsPassword,'');assert.equal(component.settingsCode,'');assert.equal(calls.length,0);assert.equal(opened,0);
    await component.login();assert.equal(calls.length,0);assert.equal(opened,0);
    component.administratorID='99';await component.login();assert.equal(calls.length,0);assert.equal(opened,0);
    component.administratorID='8';context.api=async(url,options)=>{calls.push({url,options});return {success:true,data:{action_url:'https://site.example/index.php',token:'A'.repeat(43),generation:'b'.repeat(32),expires_at:new Date(Date.now()+60000).toISOString()}};};
    await component.login();assert.equal(opened,1);assert.deepEqual({...calls[0].options.body},{administrator_id:8,confirm:true});assert.equal(forms.length,1);assert.equal(component.loginOpen,false);
    await component.toggleAuthorization();await component.toggleAuthorization();assert.equal(component.loginOpen,false);assert.equal(calls.length,1);
});

test('a pending one-click authorization rejects duplicate clicks and uses only one popup and ticket request',async()=>{
    const {component,context,calls,popup}=setup();const pending=deferred();let opened=0;
    context.window.open=()=>{opened++;return popup;};context.api=(url,options)=>{calls.push({url,options});return pending.promise;};
    const first=component.toggleAuthorization();assert.equal(opened,1);assert.equal(calls.length,1);await component.toggleAuthorization();await component.login();assert.equal(opened,1);assert.equal(calls.length,1);
    pending.resolve({success:true,data:{action_url:'https://site.example/index.php',token:'A'.repeat(43),generation:'b'.repeat(32),expires_at:new Date(Date.now()+60000).toISOString()}});await first;assert.equal(component.busy,false);
});

test('an expired panel session closes the pending popup and does not suppress the shared authentication redirect',async()=>{
    const {component,context,calls,forms,popup}=setup();
    context.api=async(url,options)=>{calls.push({url,options});if(url.endsWith('/login'))throw Object.assign(new Error('Session expired'),{code:'unauthorized',status:401});return {success:true,data:{}};};
    await component.toggleAuthorization();assert.equal(popup.closed,true);assert.equal(forms.length,0);assert.equal(component.busy,false);assert.equal(component.error,'Session expired');assert.equal(Object.hasOwn(calls[0].options,'allowAuthFailure'),false);assert(calls.at(-1).url.endsWith('/revoke'));
});

test('authorization setup opens configuration without enabling SSO or issuing a mutation',()=>{
    const {component,calls}=setup();component.status.sso_enabled=false;component.status.sso_available=false;component.status.reason_code='sso_disabled';component.enableSSO=false;
    assert.equal(component.canSetupAuthorization(),true);assert.equal(component.canAuthorize(),false);component.openAuthorizationSettings();
    assert.equal(component.settingsOpen,true);assert.equal(component.enableSSO,false);assert.equal(component.status.sso_enabled,false);assert.equal(component.loginOpen,false);assert.equal(calls.length,0);
});

test('an outdated login bridge offers explicit settings repair without issuing authorization',()=>{
    const {component,calls}=setup();component.status.sso_available=false;component.status.reason_code='bridge_unavailable';component.enableSSO=true;
    assert.equal(component.canSetupAuthorization(),true);assert.equal(component.canAuthorize(),false);
    component.openAuthorizationSettings();assert.equal(component.settingsOpen,true);assert.equal(component.enableSSO,true);assert.equal(calls.length,0);
    component.status.authentication_plugins=['two-factor'];assert.equal(component.canSetupAuthorization(),false);
});

test('unavailable and conflicting login environments never issue a ticket or open an ordinary login as fallback',async()=>{
    for (const change of [{installed:false},{sso_available:false,reason_code:'https_required'},{authentication_plugins:['two-factor']},{external_login_control:true},{administrators:[]},{administrators:[{id:-1}]}]) {
        const {component,context,calls}=setup();let opened=0;context.window.open=()=>{opened++;return null;};Object.assign(component.status,change);
        assert.equal(component.canAuthorize(),false);assert.equal(component.canSetupAuthorization(),false);assert(component.reasonText());await component.toggleAuthorization();component.openAuthorizationSettings();await component.login();
        assert.equal(component.loginOpen,false);assert.equal(component.settingsOpen,false);assert.equal(calls.length,0);assert.equal(opened,0);
    }
});

test('closing settings clears only its settings proofs and keeps the independent authorization form open',()=>{
    const {component}=setup();
    const toggle=html.match(/<details[^>]*@toggle="([^"]+)"/)[1];
    component.settingsOpen=true;component.settingsPassword='secret';component.settingsCode='123456';component.loginOpen=true;
    vm.runInNewContext('with (data) { '+toggle+' }',{data:component,$el:{open:false}});
    assert.equal(Object.hasOwn(component,'password'),false);assert.equal(Object.hasOwn(component,'code'),false);assert.equal(component.settingsPassword,'');assert.equal(component.settingsCode,'');assert.equal(component.loginOpen,true);
});

test('leaving overview or destroying the page closes pending authorization and revokes a late ticket',async()=>{
    for (const action of ['navigate','destroy']) {
        const {component,context,calls,forms,popup,watchers}=setup();const pending=deferred();
        context.api=(url,options)=>{calls.push({url,options});return url.endsWith('/login') ? pending.promise : Promise.resolve(readStatus());};
        component.init();await settle();component.loginOpen=true;
        const login=component.login();assert.equal(component.busy,true);
        if (action==='navigate') { component.detailTab='logs';watchers.get('detailTab')('logs'); } else component.destroy();
        assert.equal(popup.closed,true);assert.equal(component.loginOpen,false);
        pending.resolve({success:true,data:{action_url:'https://site.example/index.php',token:'A'.repeat(43),generation:'b'.repeat(32),expires_at:new Date(Date.now()+60000).toISOString()}});await login;
        assert.equal(forms.length,0);assert.equal(calls.at(-1).url,'/websites/1/wp-panel-access/revoke');assert.equal(component.error,'');assert.equal(component.busy,false);
    }
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
    assert.equal(calls[0].options.signal.aborted,true);assert.equal(component.settingsPassword,'');assert.equal(component.settingsCode,'');
    pending.resolve(readStatus());await first;assert.equal(component.status,null);assert.equal(component.loading,false);assert.equal(component.readController,null);
});
