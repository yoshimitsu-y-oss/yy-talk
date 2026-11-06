import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import vm from 'node:vm';
import worker, { route } from '../worker.js';
import { verifyAccess, authenticate, validateWorkspaceUser, encode } from '../src/auth.js';
import { initialRoom, reduceEvent, RoomCoordinator, physicalRoom } from '../src/room.js';

const pair=await crypto.subtle.generateKey({name:'RSASSA-PKCS1-v1_5',modulusLength:2048,publicExponent:new Uint8Array([1,0,1]),hash:'SHA-256'},true,['sign','verify']);
const jwk={...await crypto.subtle.exportKey('jwk',pair.publicKey),kid:'test-key',alg:'RS256',use:'sig'};
const pem='-----BEGIN PRIVATE KEY-----\n'+encode(await crypto.subtle.exportKey('pkcs8',pair.privateKey))+'\n-----END PRIVATE KEY-----';
const env={APP_ORIGIN:'https://dev.example.invalid',ACCESS_ISSUER:'https://test-company.cloudflareaccess.com',ACCESS_AUD:'test-audience',
  WORKSPACE_CUSTOMER_ID:'test-customer',GOOGLE_SERVICE_ACCOUNT_EMAIL:'service@example.invalid',GOOGLE_DELEGATED_ADMIN:'directory@example.invalid',GOOGLE_SERVICE_ACCOUNT_PRIVATE_KEY:pem,
  ADMIN_DIRECTORY_IDS:'["admin"]',ROOM_POLICY_JSON:'{"dev":{"allowWorkspace":true}}',LIVEKIT_URL:'wss://test.livekit.cloud',
  LIVEKIT_API_KEY:'test-only-key',LIVEKIT_API_SECRET:'test-only-secret',ROOM_NAMESPACE_SECRET:'test-only-namespace'};
const employee={id:'employee',identity:'u_employee',admin:false,email:'employee@example.invalid'};
const admin={id:'admin',identity:'u_admin',admin:true,email:'admin@example.invalid'};
const now=()=>Math.floor(Date.now()/1000);
const b64=value=>encode(new TextEncoder().encode(JSON.stringify(value)));
async function jwt(override={},header={}){
  const body={iss:env.ACCESS_ISSUER,aud:[env.ACCESS_AUD],sub:'access-sub',email:employee.email,type:'app',iat:now(),exp:now()+600,...override};
  const data=b64({alg:'RS256',kid:jwk.kid,...header})+'.'+b64(body);
  return data+'.'+encode(await crypto.subtle.sign('RSASSA-PKCS1-v1_5',pair.privateKey,new TextEncoder().encode(data)));
}
const directoryUser=(id='employee')=>({id,primaryEmail:id+'@example.invalid',customerId:env.WORKSPACE_CUSTOMER_ID,suspended:false,archived:false});
const fetcher=async url=>{
  if(url.endsWith('/certs'))return Response.json({keys:[jwk]});
  if(url==='https://oauth2.googleapis.com/token')return Response.json({access_token:'fake-oauth-token',expires_in:300});
  if(url.startsWith('https://admin.googleapis.com/')){
    const email=decodeURIComponent(url.split('/users/')[1].split('?')[0]);
    if(email.endsWith('@gmail.com'))return new Response('',{status:404});
    return Response.json(directoryUser(email.split('@')[0]));
  }
  throw new Error('Unexpected remote request');
};
const request=token=>new Request(env.APP_ORIGIN+'/',{headers:token?{'Cf-Access-Jwt-Assertion':token}:{}});

test('signed Access JWT validates signature, issuer, audience, lifetime and human app identity',async()=>{
  assert.equal((await verifyAccess(await jwt(),env,fetcher)).email,employee.email);
  for(const claims of [{iss:'https://evil.invalid'},{aud:['other']},{exp:now()-1},{iat:now()+100},{nbf:now()+100},{type:'service'},{email:undefined},{sub:''}]){
    await assert.rejects(()=>verifyAccessToken(claims),e=>e.status===401);
  }
  async function verifyAccessToken(claims){return verifyAccess(await jwt(claims),env,fetcher);}
  await assert.rejects(async()=>verifyAccess(await jwt({}, {alg:'none'}),env,fetcher),e=>e.status===401);
  const token=await jwt();const parts=token.split('.');parts[1]=b64({email:'attacker@example.invalid'});
  await assert.rejects(()=>verifyAccess(parts.join('.'),env,fetcher),e=>e.status===401);
  await assert.rejects(()=>verifyAccess('broken',env,fetcher),e=>e.status===401);
});

test('four identities: logged out denied, personal Gmail denied, employee member, explicit admin',async()=>{
  await assert.rejects(()=>authenticate(request(),env,fetcher),e=>e.status===401);
  await assert.rejects(async()=>authenticate(request(await jwt({email:'personal@gmail.com'})),env,fetcher),e=>e.status===403);
  assert.equal((await authenticate(request(await jwt()),env,fetcher)).admin,false);
  assert.equal((await authenticate(request(await jwt({email:admin.email})),env,fetcher)).admin,true);
  assert.equal(validateWorkspaceUser(directoryUser('employee'),{email:employee.email},{...env,ADMIN_DIRECTORY_IDS:'["other"]'}).admin,false);
});

test('Workspace membership is a Directory customer and active-account check, never an email suffix check',()=>{
  for(const patch of [{customerId:'foreign-customer'},{suspended:true},{suspended:undefined},{archived:true},{primaryEmail:'someone@example.invalid'},{id:'<script>'}]){
    assert.throws(()=>validateWorkspaceUser({...directoryUser(),...patch},{email:employee.email},env),e=>e.status===403);
  }
});

test('every unauthenticated asset/API/legacy path and direct host fails before assets are served',async()=>{
  let assetReads=0;const e={...env,ASSETS:{fetch(){assetReads++;return new Response('APP BODY');}}};
  for(const path of ['/','/index.html','/app.js','/app/v56.html','/worker.js','/.dev.vars','/api/session','/api/rooms/dev/token','/?room=arbitrary&user=admin']){
    const r=await worker.fetch(new Request(env.APP_ORIGIN+path),e);
    assert.equal(r.status,401,path);assert.equal(r.headers.get('Cache-Control'),'private, no-store, max-age=0');assert.equal(r.headers.get('Access-Control-Allow-Origin'),null);assert.doesNotMatch(await r.text(),/APP BODY/);
  }
  for(const host of ['https://preview.example.invalid','https://direct.workers.dev'])assert.equal((await worker.fetch(new Request(host+'/'),e)).status,403);
  assert.equal(assetReads,0);
  assert.equal((await worker.fetch(new Request(env.APP_ORIGIN+'/',{headers:{Origin:'https://evil.invalid'}}),e)).status,403);
});

function roomFixture(){const s=initialRoom();s.registered=[employee.identity,admin.identity];s.assignments[employee.identity]=['ch-video','ch1'];s.assignments[admin.identity]=['ch-video','ch1'];s.tallyAssignments={[employee.identity]:[],[admin.identity]:[]};s.users={[employee.identity]:{admin:false,seen:Date.now()},[admin.identity]:{admin:true,seen:Date.now()}};return s;}
const attacks=[{type:'init-state'},{type:'assign-channels'},{type:'add-channel'},{type:'remove-channel'},{type:'update-registered'},{type:'update-tally-assignments'},{type:'update-io-bridge'},{type:'force-talk'},{type:'force-listen'},{type:'update-video-sender'},{type:'update-monitor-title'},{type:'reorder-patch'},{type:'tally'}];
test('member cannot perform PATCH PANEL, user, routing, force-talk or tally administration',()=>{
  for(const event of attacks)assert.throws(()=>reduceEvent(roomFixture(),{...event,admin:true,senderId:admin.identity},employee),e=>e.status===403,event.type);
  assert.throws(()=>reduceEvent(roomFixture(),{type:'update-talk-states',states:{unauthorized:true}},employee),e=>e.status===403);
  assert.throws(()=>reduceEvent(roomFixture(),{type:'update-talk-states',states:{'ch-video':true}},employee),e=>e.status===403);
  const result=reduceEvent(roomFixture(),{type:'update-talk-states',states:{ch1:true},senderId:admin.identity},employee);
  assert.deepEqual(result.state.talk.u_employee,{ch1:true});assert.equal(result.state.events.at(-1).sender,employee.identity);
});

test('administrator changes state, rotates audio namespace for ACL changes, rejects malformed/XSS payloads',()=>{
  const s=roomFixture();
  const result=reduceEvent(s,{type:'assign-channels',targetUid:employee.identity,channels:['ch-video']},admin);
  assert.notEqual(result.state.generation,s.generation);assert.equal(result.rotate,true);
  assert.deepEqual(result.state.assignments.u_employee,['ch-video']);
  assert.equal(reduceEvent(s,{type:'update-monitor-title',title:'Studio A'},admin).state.monitorTitle,'Studio A');
  assert.throws(()=>reduceEvent(s,{type:'add-channel',ch:{id:'<svg>',name:'X',type:'PL'}},admin),e=>e.status===400);
  assert.throws(()=>reduceEvent(s,{type:'add-channel',ch:{id:'safe',name:'<img src=x>',type:'PL'}},admin),e=>e.status===400);
  assert.throws(()=>reduceEvent(s,JSON.parse('{"type":"update-talk-states","states":{"__proto__":true}}'),employee),e=>e.status===400);
});

function coordinator(s=roomFixture()){
  const map=new Map([['state',s]]);let alarm=null;
  const ctx={storage:{get:async k=>structuredClone(map.get(k)),put:async(k,v)=>map.set(k,structuredClone(v)),getAlarm:async()=>alarm,setAlarm:async a=>{alarm=a;}}};
  return {room:new RoomCoordinator(ctx,env),map,ctx};
}
const call=(room,actor,action,payload)=>room.fetch(new Request('https://room.internal/',{method:'POST',body:JSON.stringify({actor,room:'dev',action,payload})}));
const claims=token=>JSON.parse(Buffer.from(token.split('.')[1],'base64url'));
test('tokens are short, server-derived, party-scoped, audio/video separated; member Data is disabled',async()=>{
  const {room}=coordinator();
  const response=await call(room,employee,'token',{party:'ch1',user:admin.identity,room:'evil',admin:true});assert.equal(response.status,200);
  const token=claims((await response.json()).token);assert.equal(token.sub,employee.identity);assert.equal(token.exp-token.nbf,65);assert.equal(token.video.canPublishData,false);assert.deepEqual(token.video.canPublishSources,['microphone']);
  assert.equal(token.video.room,await physicalRoom(env,'dev',(await call(room,employee,'state').then(r=>r.json())).generation,'ch1'));
  assert.equal((await call(room,employee,'token',{party:'not-assigned'})).status,403);
  const video=claims((await call(room,employee,'token',{party:'ch-video'}).then(r=>r.json())).token);assert.equal(video.video.canPublish,false);assert.deepEqual(video.video.canPublishSources,['camera','screen_share']);assert.notEqual(video.video.room,token.video.room);
  const av=claims((await call(room,admin,'token',{party:'ch-video'}).then(r=>r.json())).token);assert.equal(av.video.canPublish,true);
});

test('HTTP router overwrites forged actor and rejects unconfigured rooms and oversized events',async()=>{
  let passed;const e={...env,ROOMS:{idFromName:x=>x,get:()=>({fetch:async r=>{passed=await r.json();return Response.json({ok:true});}})}};
  const r=await route(new Request(env.APP_ORIGIN+'/api/rooms/dev/events',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({type:'update-monitor-title',title:'X',actor:admin})}),e,employee);
  assert.equal(r.status,200);assert.equal(passed.actor.admin,false);
  await assert.rejects(()=>route(new Request(env.APP_ORIGIN+'/api/rooms/unknown/state'),e,employee),e=>e.status===403);
  await assert.rejects(()=>route(new Request(env.APP_ORIGIN+'/api/rooms/dev/events',{method:'POST',headers:{'Content-Type':'application/json'},body:'x'.repeat(33000)}),e,employee),e=>e.status===413);
});

test('ACL changes delete old media rooms before storing the new permissions; SFU failure preserves old ACL',async()=>{
  const originalFetch=globalThis.fetch;const requests=[];
  try{
    globalThis.fetch=async(url,options)=>{requests.push({url,body:JSON.parse(options.body)});return Response.json({});};
    const {room,map}=coordinator();const generation=map.get('state').generation;
    assert.equal((await call(room,admin,'event',{type:'assign-channels',targetUid:employee.identity,channels:['ch-video']})).status,200);
    assert.equal(requests.length,2);assert(requests.every(x=>x.url.endsWith('/DeleteRoom')));assert.notEqual(map.get('state').generation,generation);
    globalThis.fetch=async()=>new Response('',{status:500});
    const fixture=coordinator();const before=structuredClone(fixture.map.get('state'));
    assert.equal((await call(fixture.room,admin,'event',{type:'assign-channels',targetUid:employee.identity,channels:[]})).status,503);
    assert.deepEqual(fixture.map.get('state'),before);
  }finally{globalThis.fetch=originalFetch;}
});

test('expired membership lease evicts active SFU participants without trusting browser disconnect',async()=>{
  const originalFetch=globalThis.fetch;const requests=[];
  try{
    globalThis.fetch=async(url,options)=>{requests.push({url,body:JSON.parse(options.body)});return Response.json({});};
    const s=roomFixture();s.users.u_employee.seen=Date.now()-120000;const {room,map}=coordinator(s);map.set('logicalRoom','dev');await room.alarm();
    assert.equal(requests.length,2);assert(requests.every(x=>x.body.identity==='u_employee' && x.url.endsWith('/RemoveParticipant')));
  }finally{globalThis.fetch=originalFetch;}
});

test('built v56 keeps MediaSession/PTT fixes, parses all scripts, excludes password/MQTT/Data/legacy token endpoint',async()=>{
  const html=await fs.readFile(new URL('../public/index.html',import.meta.url),'utf8');
  assert.match(html,/v56 media display fix/);assert.match(html,/media\.playbackState='none'/);assert.match(html,/dummy\.pause\(\)/);assert.match(html,/aspect-ratio:\s*16\s*\/\s*9/);
  assert.doesNotMatch(html,/broker\.emqx\.io|mqtt\.connect|WORKER_AUTH_URL|publishData\(|管理者パスワード/);
  for(const m of html.matchAll(/<script\b[^>]*>([\s\S]*?)<\/script>/g))if(m[1].trim())new vm.Script(m[1]);
});

test('tally service JWT is bound to its own audience and exact service identity; cannot log in as a human',async()=>{
  const settings={...env,ACCESS_AUD:'bridge-audience',TALLY_SERVICE_TOKEN_ID:'approved-bridge'};
  const token=await jwt({aud:['bridge-audience'],email:undefined,common_name:'approved-bridge'});
  assert.equal((await verifyAccess(token,settings,fetcher,'tally')).common_name,'approved-bridge');
  await assert.rejects(()=>verifyAccess(token,settings,fetcher),e=>e.status===401);
  await assert.rejects(()=>verifyAccess(token,{...settings,TALLY_SERVICE_TOKEN_ID:'other-bridge'},fetcher,'tally'),e=>e.status===401);
  await assert.rejects(()=>verifyAccess(token,{...settings,ACCESS_AUD:env.ACCESS_AUD},fetcher,'tally'),e=>e.status===401);
});

test('tally principal can only change validated tally state; cannot obtain media or alter routing',async()=>{
  const bridge={id:'tally_bridge',identity:'u_tally_bridge',admin:false,kind:'tally'};
  const s=roomFixture();
  assert.deepEqual(reduceEvent(s,{type:'tally',id:2,active:true},bridge).state.tallies,[2]);
  for(const event of [{type:'assign-channels'},{type:'update-talk-states',states:{ch1:true}},{type:'force-talk'}])assert.throws(()=>reduceEvent(s,event,bridge),e=>e.status===403);
  assert.throws(()=>reduceEvent(s,{type:'tally',id:500,active:true},bridge),e=>e.status===400);
});

test('room broadcasts derive party permissions per connection; blocked members are closed; socket messages cannot mutate state',()=>{
  const {room,ctx}=coordinator();const s=roomFixture();s.assignments.u_employee=['ch1'];
  const sent=[],closed=[];
  const socket={deserializeAttachment:()=>({actor:employee}),send:value=>sent.push(JSON.parse(value)),close:(...args)=>closed.push(args)};
  ctx.getWebSockets=()=>[socket];room.broadcast(s);assert.deepEqual(sent[0].permitted,['ch1']);
  s.users.u_employee.blocked=true;room.broadcast(s);assert.equal(closed.at(-1)[0],1008);
  room.webSocketMessage(socket,'{"type":"assign-channels"}');assert.equal(closed.at(-1)[0],1008);
});
