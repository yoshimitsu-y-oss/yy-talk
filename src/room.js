import { fail, HttpError, signHmac } from './auth.js';

export const validId = v => typeof v === 'string' && /^[a-zA-Z0-9_.\-\p{L}\p{N}]{1,64}$/u.test(v) && !['__proto__','constructor','prototype'].includes(v);
const uid = v => typeof v === 'string' && /^u_[a-zA-Z0-9_-]{1,128}$/.test(v);
const object = v => v && typeof v === 'object' && !Array.isArray(v) && Object.keys(v).every(k => !['__proto__','constructor','prototype'].includes(k));
const check = v => { if (!v) fail(400,'Invalid room operation'); };
const label = (v, max=64) => typeof v === 'string' && v.length <= max && /^[\p{L}\p{N} ._\-]*$/u.test(v);
const assignments = (v, channels) => {
  check(object(v) && Object.keys(v).length <= 256);
  for (const [key,list] of Object.entries(v)) check(uid(key) && Array.isArray(list) && list.length <= 32 && list.every(c => channels.some(x => x.id === c)));
};
const channels = v => {
  check(Array.isArray(v) && v.length >= 1 && v.length <= 32 && new Set(v.map(c=>c?.id)).size === v.length);
  for (const c of v) check(object(c) && validId(c.id) && label(c.name,32) && ['PL','Local','Listen'].includes(c.type));
  check(v.some(c=>c.id === 'ch-video' && c.type === 'Listen'));
  return v.map(c=>({id:c.id,name:c.name,type:c.type,...(c.id === 'ch-video'?{fixed:true}:{})}));
};
const ioKeys = ['inAssign4wL','inAssign4wR','outAssign4wL','outAssign4wR','inAssignPgmL','inAssignPgmR'];
const gainKeys = ['inGain4wL','inGain4wR','outGain4wL','outGain4wR','inGainPgmL','inGainPgmR'];
const io = (value,list) => {
  check(object(value)); const result = {};
  for (const k of ioKeys) { check(value[k] === '' || list.some(c=>c.id === value[k] && c.id !== 'ch-video')); result[k] = value[k]; }
  for (const k of gainKeys) { check(typeof value[k] === 'number' && Number.isFinite(value[k]) && value[k] >= 0 && value[k] <= 3); result[k] = value[k]; }
  return result;
};
const tally = (v,users) => {
  check(object(v));
  for (const [key,list] of Object.entries(v)) check(uid(key) && users.includes(key) && Array.isArray(list) && list.length <= 32 && list.every(n=>Number.isInteger(n) && n >= 1 && n <= 32));
  return structuredClone(v);
};

export function initialRoom() {
  return {generation:crypto.randomUUID(),version:0,channels:[{id:'ch-video',name:'VIDEO',type:'Listen',fixed:true},{id:'ch1',name:'NEW',type:'PL'}],
    assignments:{},tallyAssignments:{},registered:[],users:{},talk:{},listen:{},tallies:[],monitorTitle:'MONITOR',videoQuality:'512000',layout:'normal',
    ioBridge:Object.fromEntries([...ioKeys.map(k=>[k,'']),...gainKeys.map(k=>[k,1])]),activeVideoSender:null,events:[]};
}

export function roomPolicy(env,room,actor) {
  let policy; try { policy=JSON.parse(env.ROOM_POLICY_JSON || '{}'); } catch { fail(503,'Room policy unavailable'); }
  if (!object(policy) || !Object.hasOwn(policy,room)) fail(403,'Room access denied');
  const rule=policy[room];
  if(!object(rule))fail(403,'Room access denied');
  if(actor.kind === 'tally'){if(room !== env.TALLY_ROOM)fail(403,'Tally room denied');return rule;}
  if (!object(rule) || !(rule.allowWorkspace === true || (Array.isArray(rule.members) && rule.members.includes(actor.id)))) fail(403,'Room access denied');
  return rule;
}
export function allowedParties(s,actor) { return actor.admin ? s.channels.map(c=>c.id) : (s.assignments[actor.identity] || []); }

export function reduceEvent(original,event,actor) {
  check(object(event) && typeof event.type === 'string');
  const s=structuredClone(original), type=event.type;
  const own=['update-talk-states','update-listen-states'].includes(type);
  if(actor.kind === 'tally' && type !== 'tally')fail(403,'Tally only');
  if (!actor.admin && actor.kind !== 'tally' && !own && !['hello','hello_reply'].includes(type)) fail(403,'Administrator required');
  let rotate=false, out=structuredClone(event);
  if (own) {
    check(object(event.states) && Object.keys(event.states).length <= 32);
    const permitted=allowedParties(s,actor);
    for (const [ch,active] of Object.entries(event.states)) {
      check(typeof active === 'boolean');
      if (active && (!permitted.includes(ch) || (type === 'update-talk-states' && !actor.admin && s.channels.find(c=>c.id === ch)?.type === 'Listen'))) fail(403,'Party access denied');
    }
    (type === 'update-talk-states' ? s.talk : s.listen)[actor.identity]=event.states;
  } else if (['hello','hello_reply'].includes(type)) {
    out={type:'hello_reply',userId:actor.identity};
  } else if (type === 'init-state') {
    s.channels=channels(event.channels); assignments(event.assignments,s.channels); s.assignments=event.assignments;
    check(Array.isArray(event.registered) && event.registered.length <= 256 && event.registered.every(uid)); s.registered=event.registered;
    s.tallyAssignments=tally(event.tallyAssignments || {},s.registered); s.ioBridge=io(event.ioBridge,s.channels);
    check(label(event.monitorTitle,128) && ['128000','256000','512000','1000000','5000000'].includes(String(event.videoQuality)) && ['normal','monitor','hybrid'].includes(event.layout));
    s.monitorTitle=event.monitorTitle; s.videoQuality=String(event.videoQuality); s.layout=event.layout; rotate=true;
    out={type,channels:s.channels,assignments:s.assignments,registered:s.registered,tallyAssignments:s.tallyAssignments,ioBridge:s.ioBridge,monitorTitle:s.monitorTitle,videoQuality:s.videoQuality,layout:s.layout};
  } else if (type === 'assign-channels') {
    check(uid(event.targetUid) && s.registered.includes(event.targetUid)); assignments({[event.targetUid]:event.channels},s.channels); s.assignments[event.targetUid]=event.channels; rotate=true;
  } else if (type === 'add-channel') {
    s.channels=channels([...s.channels,event.ch]);
    if (event.assignments) { assignments(event.assignments,s.channels); s.assignments=event.assignments; } rotate=true;
  } else if (type === 'remove-channel') {
    check(event.chId !== 'ch-video' && s.channels.some(c=>c.id === event.chId)); s.channels=s.channels.filter(c=>c.id !== event.chId);
    for (const key of Object.keys(s.assignments)) s.assignments[key]=s.assignments[key].filter(c=>c !== event.chId);
    for (const key of ioKeys) if (s.ioBridge[key] === event.chId) s.ioBridge[key]=''; rotate=true;
  } else if (type === 'update-ch-info') {
    const next=channels(event.data); check(next.length === s.channels.length && next.every(c=>s.channels.some(old=>old.id === c.id)));
    rotate=next.some(c=>s.channels.find(old=>old.id === c.id).type !== c.type); s.channels=next; out={type,data:next};
  } else if (type === 'update-registered') {
    check(Array.isArray(event.registered) && event.registered.length <= 256 && event.registered.every(uid)); s.registered=event.registered;
    for (const key of Object.keys(s.assignments)) if (!s.registered.includes(key)) { s.assignments[key]=[]; if(s.users[key])s.users[key].blocked=true; } rotate=true;
  } else if (type === 'restore-user') {
    check(uid(event.identity));if(s.users[event.identity])s.users[event.identity].blocked=false;if(!s.registered.includes(event.identity))s.registered.push(event.identity);s.assignments[event.identity] ||= [];
  } else if (type === 'update-tally-assignments') {
    s.tallyAssignments=tally(event.assignments,s.registered);
  } else if (type === 'update-io-bridge') {
    const next=io(event.ioBridge,s.channels); rotate=ioKeys.some(k=>next[k] !== s.ioBridge[k]); s.ioBridge=next; out={type,ioBridge:next};
  } else if (type === 'set-video-quality') {
    check(['128000','256000','512000','1000000','5000000'].includes(String(event.value))); s.videoQuality=String(event.value);
  } else if (type === 'update-monitor-title') {
    check(label(event.title,128)); s.monitorTitle=event.title;
  } else if (type === 'update-video-sender') {
    check(event.senderId === null || event.senderId === actor.identity); check(event.sourceText === undefined || (typeof event.sourceText === 'string' && event.sourceText.length <= 128)); s.activeVideoSender=event.senderId;
  } else if (type === 'reorder-patch') {
    check(Array.isArray(event.channelOrder) && event.channelOrder.length === s.channels.length && new Set(event.channelOrder).size === s.channels.length && event.channelOrder.every(id=>s.channels.some(c=>c.id === id)));
    check(Array.isArray(event.userOrder) && event.userOrder.length === s.registered.length && new Set(event.userOrder).size === s.registered.length && event.userOrder.every(id=>s.registered.includes(id)));
    s.channels.sort((a,b)=>event.channelOrder.indexOf(a.id)-event.channelOrder.indexOf(b.id)); s.registered=event.userOrder;
  } else if (type === 'force-talk' || type === 'force-listen') {
    check(uid(event.targetUid) && typeof event.active === 'boolean' && (s.assignments[event.targetUid] || []).includes(event.chId));
    if (type === 'force-talk' && event.active && s.channels.find(c=>c.id === event.chId)?.type === 'Listen' && !s.users[event.targetUid]?.admin) fail(403,'Listen-only party');
    const map=type === 'force-talk' ? s.talk : s.listen; map[event.targetUid] ||= {}; map[event.targetUid][event.chId]=event.active;
  } else if (type === 'tally') {
    check(Number.isInteger(event.id) && event.id >= 1 && event.id <= 32 && typeof event.active === 'boolean'); s.tallies=s.tallies.filter(id=>id !== event.id); if(event.active)s.tallies.push(event.id);
  } else fail(400,'Unknown room operation');
  if(rotate)s.generation=crypto.randomUUID();
  s.version++; s.events.push({version:s.version,sender:actor.identity,data:['force-talk','force-listen','update-video-sender'].includes(type)?out:{type}}); s.events=s.events.slice(-128);
  return {state:s,rotate};
}

export async function physicalRoom(env,logical,generation,party) {
  const key=await crypto.subtle.importKey('raw',new TextEncoder().encode(env.ROOM_NAMESPACE_SECRET),{name:'HMAC',hash:'SHA-256'},false,['sign']);
  const digest=await crypto.subtle.sign('HMAC',key,new TextEncoder().encode(JSON.stringify([logical,generation,party])));
  return `yy_${Array.from(new Uint8Array(digest)).map(b=>b.toString(16).padStart(2,'0')).join('').slice(0,40)}`;
}
export async function livekitRpc(env,method,body) {
  if(!/^wss:\/\/[a-z0-9-]+\.livekit\.cloud$/.test(env.LIVEKIT_URL || '') || !env.LIVEKIT_API_KEY || !env.LIVEKIT_API_SECRET)fail(503,'Media not configured');
  const now=Math.floor(Date.now()/1000);
  const token=await signHmac({iss:env.LIVEKIT_API_KEY,sub:'yy-worker',nbf:now-5,exp:now+30,video:{roomAdmin:true,roomCreate:true,room:body.room}},env.LIVEKIT_API_SECRET);
  const response=await fetch(`${env.LIVEKIT_URL.replace('wss:','https:')}/twirp/livekit.RoomService/${method}`,{method:'POST',redirect:'error',signal:AbortSignal.timeout(5000),headers:{Authorization:`Bearer ${token}`,'Content-Type':'application/json'},body:JSON.stringify(body)});
  if(response.status === 404)return;
  if(!response.ok)fail(503,'Media permission update unavailable');
}

export class RoomCoordinator {
  constructor(ctx,env){this.ctx=ctx;this.env=env;this.tail=Promise.resolve();}
  fetch(request){const op=this.tail.then(()=>this.handle(request));this.tail=op.catch(()=>{});return op;}
  async handle(request){
    try{
      const websocket=request.headers.get('Upgrade')?.toLowerCase() === 'websocket';
      const {actor,room,action,payload}=websocket ? {actor:JSON.parse(request.headers.get('X-YY-Actor')),room:request.headers.get('X-YY-Room'),action:'socket'} : await request.json(); // Internal binding only; actor is overwritten by the authenticated Worker.
      check(actor && uid(actor.identity) && typeof actor.admin === 'boolean' && validId(room));
      const policy=roomPolicy(this.env,room,actor);
      let s=await this.ctx.storage.get('state') || initialRoom(); const oldUser=s.users[actor.identity];
      if(oldUser?.blocked)fail(403,'Room access denied');
      if(oldUser && oldUser.admin !== actor.admin)await this.evict(s,room,actor.identity);
      if(actor.kind === 'tally' && action !== 'event')fail(403,'Tally only');
      if(actor.kind !== 'tally' && !s.registered.includes(actor.identity)){
        check(s.registered.length < 256);s.registered.push(actor.identity);
        s.assignments[actor.identity]=(policy.defaultParties || s.channels.map(c=>c.id)).filter(id=>s.channels.some(c=>c.id === id));s.tallyAssignments[actor.identity]=[];
      }
      s.users[actor.identity]={admin:actor.admin,email:actor.email,seen:Date.now()};await this.ctx.storage.put('logicalRoom',room);
      if(action === 'event'){
        const result=reduceEvent(s,payload,actor);if(result.rotate)await this.deleteMedia(s,room);s=result.state;
      }else if(action === 'token'){
        const party=payload?.party;
        if(!allowedParties(s,actor).includes(party) || !s.channels.some(c=>c.id === party))fail(403,'Party access denied');
        if(!this.env.ROOM_NAMESPACE_SECRET || !this.env.LIVEKIT_API_KEY || !this.env.LIVEKIT_API_SECRET || !/^wss:\/\/[a-z0-9-]+\.livekit\.cloud$/.test(this.env.LIVEKIT_URL || ''))fail(503,'Media not configured');
        const channel=s.channels.find(c=>c.id === party),now=Math.floor(Date.now()/1000),video=party === 'ch-video';
        const canPublish=video ? actor.admin : actor.admin || channel.type !== 'Listen';
        const token=await signHmac({iss:this.env.LIVEKIT_API_KEY,sub:actor.identity,nbf:now-5,exp:now+60,jti:crypto.randomUUID(),video:{roomJoin:true,room:await physicalRoom(this.env,room,s.generation,party),canPublish,canSubscribe:true,canPublishData:false,canUpdateOwnMetadata:false,canPublishSources:video?['camera','screen_share']:['microphone']}},this.env.LIVEKIT_API_SECRET);
        await this.persist(s);return Response.json({token,url:this.env.LIVEKIT_URL,generation:s.generation,expiresIn:60});
      }else if(action === 'socket'){
        const pair=new WebSocketPair();this.ctx.acceptWebSocket(pair[1],[actor.identity]);pair[1].serializeAttachment({actor});await this.persist(s);pair[1].send(JSON.stringify(snapshot(s,actor)));return new Response(null,{status:101,webSocket:pair[0]});
      }else if(action !== 'state')fail(404,'Not found');
      await this.persist(s);this.broadcast(s);return Response.json(snapshot(s,actor));
    }catch(e){return Response.json({error:e instanceof HttpError?e.message:'Room service unavailable'},{status:e.status || 503});}
  }
  broadcast(s){for(const ws of this.ctx.getWebSockets?.() || []){try{const {actor}=ws.deserializeAttachment();const user=s.users[actor.identity];if(!user || user.blocked || user.seen<Date.now()-90000){ws.close(1008,'Authentication expired');continue;}ws.send(JSON.stringify(snapshot(s,{...actor,admin:user.admin})));}catch{ws.close(1011,'Sync failed');}}}
  webSocketMessage(ws){ws.close(1008,'Use authenticated HTTP API for changes');}
  webSocketClose(ws,code){ws.close(code);}
  async persist(s){await this.ctx.storage.put('state',s);if(!await this.ctx.storage.getAlarm())await this.ctx.storage.setAlarm(Date.now()+30000);}
  async deleteMedia(s,room){for(const ch of s.channels)await livekitRpc(this.env,'DeleteRoom',{room:await physicalRoom(this.env,room,s.generation,ch.id)});}
  async evict(s,room,identity){for(const ch of s.channels)await livekitRpc(this.env,'RemoveParticipant',{room:await physicalRoom(this.env,room,s.generation,ch.id),identity});}
  async alarm(){
    const op=this.tail.then(async()=>{
      const s=await this.ctx.storage.get('state'),room=await this.ctx.storage.get('logicalRoom');if(!s || !room)return;
      for(const [identity,user] of Object.entries(s.users))if(user.seen < Date.now()-90000 || user.blocked){await this.evict(s,room,identity);delete s.talk[identity];delete s.listen[identity];}
      this.broadcast(s);await this.ctx.storage.put('state',s);await this.ctx.storage.setAlarm(Date.now()+30000);
    });this.tail=op.catch(()=>{});return op;
  }
}

export function snapshot(s,actor){return {names:Object.fromEntries(Object.entries(s.users).filter(([,u])=>u.email).map(([id,u])=>[id,u.email])),generation:s.generation,version:s.version,channels:s.channels,assignments:s.assignments,tallyAssignments:s.tallyAssignments,registered:s.registered,monitorTitle:s.monitorTitle,videoQuality:s.videoQuality,layout:s.layout,ioBridge:s.ioBridge,admin:actor.admin,activeVideoSender:s.activeVideoSender,talk:s.talk,listen:s.listen,tallies:s.tallies,events:s.events,permitted:allowedParties(s,actor)};}
