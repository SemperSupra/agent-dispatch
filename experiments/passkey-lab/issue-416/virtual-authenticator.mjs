// Node 22 + Chromium DevTools WebAuthn. Synthetic localhost-only test.
// No real passkeys, accounts, biometric templates or browser profile reuse.
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import {spawn,spawnSync} from 'node:child_process';
import {setTimeout as delay} from 'node:timers/promises';
const hash=x=>crypto.createHash('sha256').update(x).digest();
const log=x=>console.log('PASSKEY_R0_'+x);
const tmp=fs.mkdtempSync(path.join(os.tmpdir(),'r0-webauthn-'));
const server=http.createServer((_q,r)=>{
 r.writeHead(200,{'content-type':'text/html','cache-control':'no-store'});
 r.end('<!doctype html><title>Synthetic Passkey Lab</title>TEST_ONLY');
});
let chrome,ws;
try {
 await new Promise((resolve,reject)=>{server.once('error',reject);server.listen(0,'::',resolve);});
 const origin='http://localhost:'+server.address().port;
 const rpId='localhost';
 const binary=process.env.CHROME_PATH||['google-chrome','chromium','chromium-browser'].find(c=>spawnSync('which',[c],{stdio:'ignore'}).status===0);
 assert(binary,'Chrome or Chromium is required');
 const profile=path.join(tmp,'profile');
 chrome=spawn(binary,['--headless=new','--no-sandbox','--disable-gpu','--disable-dev-shm-usage',
  '--disable-background-networking','--disable-component-update','--no-first-run',
  '--no-default-browser-check','--remote-debugging-port=0','--remote-debugging-address=127.0.0.1',
  '--user-data-dir='+profile,'about:blank'],{stdio:['ignore','ignore','pipe']});
 let err='';chrome.stderr.on('data',d=>{if(err.length<2000)err+=d.toString()});
 const portFile=path.join(profile,'DevToolsActivePort');
 for(let i=0;i<150&&!fs.existsSync(portFile);i++){if(chrome.exitCode!==null)throw Error('Chrome bootstrap exited '+err.slice(-200));await delay(100)}
 assert(fs.existsSync(portFile),'Chrome CDP port unavailable');
 const port=Number(fs.readFileSync(portFile,'utf8').split('\n')[0]);
 const targetResp=await fetch('http://127.0.0.1:'+port+'/json/new?'+encodeURIComponent(origin),{method:'PUT'});
 assert(targetResp.ok,'CDP page creation failed');
 const target=await targetResp.json();
 ws=new WebSocket(target.webSocketDebuggerUrl);
 await new Promise((resolve,reject)=>{ws.addEventListener('open',resolve,{once:true});ws.addEventListener('error',reject,{once:true})});
 const pending=new Map();let id=0;
 ws.addEventListener('message',e=>{const m=JSON.parse(e.data);const p=pending.get(m.id);if(!p)return;pending.delete(m.id);if(m.error)p.reject(Error(JSON.stringify(m.error)));else p.resolve(m.result)});
 const cdp=(method,params={})=>new Promise((resolve,reject)=>{
  const key=++id;const timer=setTimeout(()=>{pending.delete(key);reject(Error('CDP timed out: '+method))},30000);
  timer.unref();
  pending.set(key,{resolve:x=>{clearTimeout(timer);resolve(x)},reject:e=>{clearTimeout(timer);reject(e)}});
  ws.send(JSON.stringify({id:key,method,params}));
 });
 const evaluate=async expression=>{
  const r=await cdp('Runtime.evaluate',{expression,returnByValue:true,awaitPromise:true,userGesture:true});
  if(r.exceptionDetails)throw Error('browser evaluation failed: '+r.exceptionDetails.text);
  return r.result.value;
 };
 await cdp('Page.enable');
 const nav=await cdp('Page.navigate',{url:origin});
 if(nav.errorText)throw Error('localhost navigation failed: '+nav.errorText);
 let ready=false;
 for(let i=0;i<140;i++){
  const x=await evaluate('document.readyState + ":" + location.origin');
  if(x==='complete:'+origin){ready=true;break}await delay(50);
 }
 assert(ready,'secure localhost test RP not loaded');
 assert.equal(await evaluate('isSecureContext'),true);
 assert.equal(await evaluate('typeof PublicKeyCredential'),'function');
 await cdp('WebAuthn.enable');
 const {authenticatorId}=await cdp('WebAuthn.addVirtualAuthenticator',{options:{
  protocol:'ctap2',transport:'internal',hasResidentKey:true,hasUserVerification:true,
  isUserVerified:true,automaticPresenceSimulation:true,
 }});
 const arr=x=>'['+Array.from(x).join(',')+']';
 const enc='b=>btoa(String.fromCharCode(...new Uint8Array(b)))';
 const createChallenge=crypto.randomBytes(32);
 const created=await evaluate(`(async()=>{const enc=${enc};
  try{const c=await navigator.credentials.create({publicKey:{
   challenge:new Uint8Array(${arr(createChallenge)}),rp:{id:'localhost',name:'R0 Synthetic RP'},
   user:{id:new Uint8Array([84,69,83,84,45,79,78,76,89]),name:'test@example.invalid',displayName:'Test identity'},
   pubKeyCredParams:[{type:'public-key',alg:-7}],timeout:12000,attestation:'none',
   authenticatorSelection:{residentKey:'required',userVerification:'required'}}});
   return {ok:true,id:c.id,rawId:enc(c.rawId),client:enc(c.response.clientDataJSON),
    publicKey:enc(c.response.getPublicKey()),algorithm:c.response.getPublicKeyAlgorithm(),
    authData:enc(c.response.getAuthenticatorData())};
  }catch(e){return {ok:false,error:e.name}}})()`);
 assert(created?.ok,'actual browser passkey creation failed: '+JSON.stringify(created));
 assert.equal(created.algorithm,-7);
 const key=crypto.createPublicKey({key:Buffer.from(created.publicKey,'base64'),format:'der',type:'spki'});
 const raw=Buffer.from(created.rawId,'base64');
 assert(raw.length>=16);
 const registration=JSON.parse(Buffer.from(created.client,'base64').toString());
 assert.equal(registration.type,'webauthn.create');
 assert.equal(registration.origin,origin);
 assert.equal(registration.challenge,createChallenge.toString('base64url'));
 const ad=Buffer.from(created.authData,'base64');
 assert.equal(ad.subarray(0,32).toString('hex'),hash(rpId).toString('hex'));
 assert((ad[32]&5)===5,'creation must report UP and UV');
 log('CDP_ACTUAL_BROWSER_CREDENTIAL_REGISTRATION=PASS');
 const seen=new Set();
 function verify(a,challenge,expectedOrigin=origin){
  const data=Buffer.from(a.authData,'base64'),client=Buffer.from(a.client,'base64');
  const c=JSON.parse(client.toString()), token=challenge.toString('base64url');
  assert.equal(c.type,'webauthn.get');assert.equal(c.origin,expectedOrigin);
  assert.equal(c.challenge,token);assert(!seen.has(token),'replayed challenge');
  assert.equal(data.subarray(0,32).toString('hex'),hash(rpId).toString('hex'));
  assert((data[32]&5)===5,'UP and UV required');
  const message=Buffer.concat([data,hash(client)]);
  assert(crypto.verify('sha256',message,key,Buffer.from(a.signature,'base64')),'signature failed');
  seen.add(token);
 }
 async function get(challenge){
  return await evaluate(`(async()=>{const enc=${enc};
    try{const c=await navigator.credentials.get({publicKey:{
      challenge:new Uint8Array(${arr(challenge)}),rpId:'localhost',
      allowCredentials:[{type:'public-key',id:new Uint8Array(${arr(raw)})}],
      userVerification:'required',timeout:3000}});
      return {ok:true,authData:enc(c.response.authenticatorData),client:enc(c.response.clientDataJSON),
        signature:enc(c.response.signature)};
    }catch(e){return {ok:false,error:e.name}}})()`);
 }
 const c1=crypto.randomBytes(32),a1=await get(c1);
 assert(a1?.ok,'WebAuthn get failed: '+JSON.stringify(a1));
 verify(a1,c1);
 assert.throws(()=>verify(a1,c1),/replayed challenge/);
 assert.throws(()=>verify(a1,crypto.randomBytes(32)),/Expected values to be strictly equal/);
 const originClient=JSON.parse(Buffer.from(a1.client,'base64').toString());
 assert.equal(originClient.origin,origin);
 const badData=Buffer.from(a1.authData,'base64');badData[0]^=1;
 const badSig=Buffer.from(a1.signature,'base64');badSig[0]^=1;
 assert.equal(crypto.verify('sha256',Buffer.concat([badData,hash(Buffer.from(a1.client,'base64'))]),key,Buffer.from(a1.signature,'base64')),false);
 assert.equal(crypto.verify('sha256',Buffer.concat([Buffer.from(a1.authData,'base64'),hash(Buffer.from(a1.client,'base64'))]),key,badSig),false);
 log('CRYPTOGRAPHIC_ASSERTION_RP_ORIGIN_CHALLENGE_REPLAY_AND_TAMPER=PASS');
 await cdp('WebAuthn.setUserVerified',{authenticatorId,isUserVerified:false});
 const neg=await get(crypto.randomBytes(32));
 if(neg?.ok)assert.equal(Buffer.from(neg.authData,'base64')[32]&4,0,'UV=false unexpectedly claimed verified');
 log('VIRTUAL_USER_VERIFICATION_FALSE_REJECTED_OR_UNVERIFIED=PASS');
 await cdp('WebAuthn.setUserVerified',{authenticatorId,isUserVerified:true});
 const c2=crypto.randomBytes(32),a2=await get(c2);
 assert(a2?.ok,'UV reenable failed: '+JSON.stringify(a2));verify(a2,c2);
 const {credentials}=await cdp('WebAuthn.getCredentials',{authenticatorId});
 assert(credentials?.length>=1,'new test passkey absent from authenticator');
 await cdp('WebAuthn.removeVirtualAuthenticator',{authenticatorId});
 log('UV_REENABLED_SIGNING_AND_VIRTUAL_CREDENTIAL_DESTROYED=PASS');
 log('ANDROID_BIOMETRIC_SECURITY_AND_REAL_ACCOUNTS=NOT_TESTED');
}finally{
 if(ws)try{ws.close()}catch{}
 if(chrome){chrome.kill('SIGTERM');await delay(300);if(chrome.exitCode===null)chrome.kill('SIGKILL')}
 await new Promise(resolve=>server.close(resolve));
 fs.rmSync(tmp,{recursive:true,force:true});
}
