const fs=require('fs'),vm=require('vm'),assert=require('assert');
const code=fs.readFileSync('web/templates/ssh_port.html','utf8').match(/<script>([\s\S]*?)<\/script>/)[1];
const calls=[];let failConfirm=true;
const ctx={t:x=>x,confirmModal:async()=>true,showToast:()=>{},clearTimeout:()=>{},setTimeout:()=>1,api:async(path,opts)=>{
 calls.push({path,opts});
 if(path.endsWith('/confirm')){if(failConfirm)throw Error('new SSH session not verified');return {success:true};}
 if(opts?.method==='POST')return {success:true,data:{token:'proof-token',new_port:2222,old_port:22,deadline:'2030-01-01',verify_command:'test command'}};
 return {success:true,data:{port:22,available:true}};
}};
vm.createContext(ctx);vm.runInContext(code,ctx);
(async()=>{
 const m=ctx.sshPortManager();m.$dispatch=()=>{};await m.refresh();m.port=2222;
 await m.begin();assert.equal(calls.filter(x=>x.opts?.method==='POST').length,0,'must acknowledge cloud firewall');
 m.cloudReady=true;await m.begin();assert.equal(m.change.new_port,2222);assert(!calls.some(x=>x.path.endsWith('/confirm')),'never automatically confirm');
 await m.confirm();assert(m.change,'failed verification must not appear successful');assert(m.error.includes('not verified'));
 failConfirm=false;await m.confirm();assert.equal(m.change,null);assert.equal(m.port,'');assert.equal(m.cloudReady,false);
 console.log('SSH change acknowledgement, verification failure and confirmation flow passed');
})().catch(e=>{console.error(e);process.exit(1)});
