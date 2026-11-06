import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import vm from 'node:vm';

const source=await fs.readFile(new URL('../src/client-security.js',import.meta.url),'utf8');
function raw(channel='mic'){
  return {channel,enabled:true,readyState:'live',clone(){return raw(this.channel);},stop(){this.readyState='ended';}};
}
function fixture(){
  const published=[],mixers=[],closed=[];
  class Room{
    constructor(){this.state='disconnected';this.handlers={};this.localParticipant={publishTrack:async(track,options)=>{
      const pub={track:{mediaStreamTrack:track,stop:()=>track.stop()},name:options.name};published.push({room:this.room,options,pub});return pub;
    },unpublishTrack:async()=>{}};}
    on(name,cb){this.handlers[name]=cb;return this;}
    async connect(url,token){this.state='connected';this.room=token;}
    async disconnect(){this.state='disconnected';closed.push(this.room);}
    async startAudio(){}
  }
  const state={room:{state:'connected',disconnect:async()=>{},connect:async()=>{},localParticipant:{}},roomId:'dev',myUserId:'u_employee',isAdmin:false,channels:[{id:'ch-video',type:'Listen'},{id:'ch1',type:'PL'},{id:'ch2',type:'PL'}],
    mediaCalls:{},talkStates:{ch1:true,ch2:false},isMasterMicMuted:false,ioBridge:{enabled:false,inAssign4wL:'ch1',inAssign4wR:'ch2'}};
  const pairs=[];
  state.audioCtx={createMediaStreamSource:()=>({connect(){},disconnect(){}}),createChannelSplitter:()=>({connect(dest,index){dest.track.channel=index;pairs.push({dest,index});},disconnect(){}}),
    createMediaStreamDestination:()=>{const track=raw();return {track,stream:{getAudioTracks:()=>[track],getTracks:()=>[track]}};}};
  const context=vm.createContext({state,window:{addEventListener(){}},location:{origin:'https://dev.example.invalid'},
    MediaStream:class{constructor(tracks){this.tracks=tracks;}},LivekitClient:{Room,Track:{Kind:{Audio:'audio'},Source:{Microphone:'microphone'}},RoomEvent:{TrackSubscribed:'track',TrackUnsubscribed:'untrack',Reconnecting:'reconnecting'}},
    setupPeerMixer:call=>mixers.push(call),yySafeTalkOff(){},setTimeout,clearTimeout,console});
  new vm.Script(source+'\nglobalThis.client=security;').runInContext(context);
  const client=context.client;
  client.latest={generation:'g1',permitted:['ch-video','ch1','ch2']};client.generation='g1';
  client.token=async party=>({token:party,url:'wss://test.livekit.cloud',generation:'g1'});
  return {client,state,published,mixers,pairs,closed};
}

test('TALK and master mute enable only the intended party microphone clones',async()=>{
  const {client,state,published}=fixture();await client.publishMic(raw());
  assert.equal(published.length,2);assert(published.every(p=>p.options.name==='mic'));
  assert.equal(published.find(p=>p.room==='ch1').pub.track.mediaStreamTrack.enabled,true);
  assert.equal(published.find(p=>p.room==='ch2').pub.track.mediaStreamTrack.enabled,false);
  state.isMasterMicMuted=true;client.mute();assert(published.every(p=>p.pub.track.mediaStreamTrack.enabled===false));
  state.isMasterMicMuted=false;state.talkStates={ch1:false,ch2:true};client.mute();
  assert.equal(published.find(p=>p.room==='ch1').pub.track.mediaStreamTrack.enabled,false);
  assert.equal(published.find(p=>p.room==='ch2').pub.track.mediaStreamTrack.enabled,true);
});

test('4W L/R split before publication: each party receives only its own channel; unauthorized party never connects',async()=>{
  const {client,state,published,pairs}=fixture();state.isAdmin=true;state.ioBridge.enabled=true;
  await client.publishIO(raw('stereo'),'io_4w_stereo');
  assert.equal(pairs.length,2);
  assert.equal(published.find(p=>p.options.name==='io_4w_l').room,'ch1');
  assert.equal(published.find(p=>p.options.name==='io_4w_l').pub.track.mediaStreamTrack.channel,0);
  assert.equal(published.find(p=>p.options.name==='io_4w_r').room,'ch2');
  assert.equal(published.find(p=>p.options.name==='io_4w_r').pub.track.mediaStreamTrack.channel,1);
  client.latest.permitted=['ch-video','ch1'];await client.reconcile();assert.equal(client.parties.has('ch2'),false);
});

test('party receiver tags inbound audio with its fixed party, never trusts track name to select another bus',async()=>{
  const {client,state,mixers}=fixture();await client.reconcile();
  const entry=client.parties.get('ch1');
  entry.room.handlers.track({kind:'audio',mediaStreamTrack:raw()},{trackSid:'track1',trackName:'io_4w_r'},{identity:'u_other'});
  assert.equal(mixers.length,1);assert.equal(mixers[0].secureParty,'ch1');assert.equal(mixers[0].secureSender,'u_other');
  assert.equal(Object.keys(state.mediaCalls).length,1);
});

test('Listen-only party obtains receive-only connections and never publishes microphone',async()=>{
  const {client,state,published}=fixture();state.channels.find(c=>c.id==='ch2').type='Listen';await client.publishMic(raw());
  assert.equal(published.length,1);assert.equal(published[0].room,'ch1');assert(client.parties.has('ch2'));
});

test('PGM L/R are split and member cannot publish bridge sources',async()=>{
  const {client,state,published}=fixture();await assert.rejects(()=>client.publishIO(raw(),'io_pgm_stereo'));
  state.isAdmin=true;state.ioBridge.inAssignPgmL='ch2';state.ioBridge.inAssignPgmR='ch1';await client.publishIO(raw(),'io_pgm_stereo');
  assert.equal(published.find(p=>p.options.name==='io_pgm_l').room,'ch2');assert.equal(published.find(p=>p.options.name==='io_pgm_r').room,'ch1');
});

test('namespace change restores a disconnected SFU session using a fresh token, then reconnects authorized parties',async()=>{
  const {client,state}=fixture();let connects=0;
  state.hasSuccessfullyConnected=true;state.room.state='disconnected';state.room.connect=async()=>{connects++;state.room.state='connected';};
  client.latest.generation='g2';client.token=async party=>({token:party,url:'wss://test.livekit.cloud',generation:'g2'});
  await client.reconcile();assert.equal(connects,1);assert.equal(client.generation,'g2');assert.equal(client.parties.size,2);
});

test('v56 JOIN unlocks audio before awaiting network authentication, preserving iOS user activation',async()=>{
  const html=await fs.readFile(new URL('../public/index.html',import.meta.url),'utf8');
  const start=html.indexOf('const joinNetwork = async function');const end=html.indexOf('const btn = isAdmin',start);const join=html.slice(start,end);
  assert(join.indexOf('joinAudioPromise=activateAudioForJoin')>=0);assert(join.indexOf('joinAudioPromise=activateAudioForJoin')<join.indexOf('await security.join'));
});
