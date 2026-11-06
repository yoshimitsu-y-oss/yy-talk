// Injected into v56's lexical scope by scripts/build.py. No credentials live here.
const security = {
  applying:false, generation:null, config:null, version:0, timer:null, busy:false, queue:Promise.resolve(),
  parties:new Map(), mic:null, io:new Map(), videoUrl:'', rotating:false,
  async api(path,body){
    const r=await fetch(path,{method:body === undefined?'GET':'POST',credentials:'same-origin',cache:'no-store',
      headers:body === undefined?{}:{'Content-Type':'application/json'},body:body === undefined?undefined:JSON.stringify(body)});
    const value=await r.json();if(!r.ok){const e=new Error(value.error || '通信できません');e.status=r.status;throw e;}return value;
  },
  label(id){return this.names?.[id] || id;},
  path(action){return '/api/rooms/'+encodeURIComponent(state.roomId)+'/'+action;},
  async token(party){const data=await this.api(this.path('token'),{party});this.videoUrl=data.url;return data;},
  async join(room){
    this.stop();state.hasSuccessfullyConnected=false;await state.room?.disconnect?.();await this.closeMedia();this.latest=null;this.generation=null;this.version=0;this.config=null;const user=await this.api('/api/session');state.roomId=room;state.myUserId=user.identity;state.isAdmin=user.admin;
    const snapshot=await this.api(this.path('state'));this.apply(snapshot);return user;
  },
  send(payload){
    if(this.applying || !state.roomId || ['hello','hello_reply'].includes(payload.type))return Promise.resolve();
    const operation=this.queue.then(async()=>{
      const snapshot=await this.api(this.path('events'),payload);this.apply(snapshot);await this.reconcile();
    });
    this.queue=operation.catch(async e=>{
      yySafeTalkOff('操作が許可されませんでした',true);uiLog(e.message,'#ef4444');
      try{this.config=null;this.apply(await this.api(this.path('state')));}catch{this.stop();}
    });return this.queue;
  },
  apply(s){
    this.applying=true;
    try{
      const signature=JSON.stringify([s.channels,s.assignments,s.registered,s.tallyAssignments,s.ioBridge,s.monitorTitle,s.videoQuality,s.layout,s.names]);
      if(signature !== this.config){
        this.config=signature;
        handleNetworkData({type:'init-state',channels:s.channels,assignments:s.assignments,registered:s.registered,tallyAssignments:s.tallyAssignments,
          ioBridge:s.ioBridge,monitorTitle:s.monitorTitle,videoQuality:s.videoQuality,layout:s.layout},'server');
      }
      this.names=s.names || {};
      state.activeVideoSender=s.activeVideoSender;
      state.remoteTalkStates=s.talk;state.remoteListenStates=s.listen;
      for(const event of s.events || [])if(event.version > this.version && ['force-talk','force-listen','update-video-sender'].includes(event.data.type))handleNetworkData(event.data,event.sender);
      activeTallies.clear();for(const id of s.tallies || [])activeTallies.add(id);evaluateTallyGlow();
      if(typeof s.admin === 'boolean' && state.isAdmin !== s.admin){state.isAdmin=s.admin;if(!s.admin)state.ioBridge.enabled=false;}
      document.querySelectorAll('.admin-only').forEach(el=>el.style.display=state.isAdmin?'flex':'none');
      this.latest=s;this.version=s.version;updateAudioRouting();
    }finally{this.applying=false;}
  },
  openSocket(){
    if(!this.running)return;
    const socket=new WebSocket(location.origin.replace('https:','wss:')+this.path('socket'));this.socket=socket;
    socket.onmessage=async event=>{try{this.apply(JSON.parse(event.data));await this.reconcile();}catch{socket.close();}};
    socket.onclose=()=>{clearTimeout(this.socketRenew);if(this.socket===socket && this.running)this.socketRetry=setTimeout(()=>this.openSocket(),1500);};
    this.socketRenew=setTimeout(()=>socket.close(1000,'Reauthenticate'),25000);
  },
  start(){
    this.running=true;this.openSocket();
    if(this.timer)clearTimeout(this.timer);
    const tick=async()=>{
      try{this.apply(await this.api(this.path('state')));await this.reconcile();}
      catch(e){yySafeTalkOff('認証または同期を確認できません',true);uiLog(e.message,'#ef4444');await this.closeMedia();if(e.status===401 || e.status===403){state.hasSuccessfullyConnected=false;this.stop();await state.room?.disconnect?.();return;}}
      this.timer=setTimeout(tick,5000);
    };this.timer=setTimeout(tick,5000);
  },
  async closeMedia(){for(const entry of this.parties.values())await entry.room.disconnect();this.parties.clear();for(const key of Object.keys(state.mediaCalls))if(state.mediaCalls[key]?.secureParty)this.removeCall(key);},
  stop(){this.running=false;clearTimeout(this.socketRetry);clearTimeout(this.socketRenew);this.socket?.close();if(this.timer)clearTimeout(this.timer);this.timer=null;this.closeMedia().catch(()=>{});},
  removeCall(key){const c=state.mediaCalls[key];if(!c)return;try{c.source?.disconnect();c.audioEl?.pause();for(const g of Object.values(c.chGains || {})){g.gain.disconnect();g.panner.disconnect();}}catch{}delete state.mediaCalls[key];},
  async reconcile(){
    if(this.busy || !this.latest || !state.room || (state.room.state !== 'connected' && !state.hasSuccessfullyConnected))return;
    this.busy=true;
    try{
      const s=this.latest;
      const videoPermitted=(s.permitted || []).includes('ch-video');
      if(!videoPermitted){await this.closeMedia();await state.room.disconnect();throw new Error('VIDEOパーティーへの参加権限が必要です');}
      if((this.generation && this.generation !== s.generation) || state.room.state !== 'connected'){
        this.rotating=true;if(typeof autoReconnectTimer !== 'undefined'){clearTimeout(autoReconnectTimer);autoReconnectTimer=null;}yySafeTalkOff('パーティー権限を更新',true);await this.closeMedia();
        const videoRaw=state.currentLocalVideoTrack?.mediaStreamTrack;const localVideo=videoRaw?.readyState==='live'?videoRaw.clone():null;
        const restoreDevice=state.currentVideoSourceId;
        await state.room.disconnect();const token=await this.token('ch-video');await state.room.connect(token.url,token.token);
        if(localVideo && state.isAdmin){const track=new LivekitClient.LocalVideoTrack(localVideo);await state.room.localParticipant.publishTrack(track,{name:'camera',source:LivekitClient.Track.Source.Camera});state.currentLocalVideoTrack=track;}
        else if(state.isAdmin && restoreDevice && !['off','screen'].includes(restoreDevice)){await openSelectedVideoSource(restoreDevice,{watchdog:true});}
        this.rotating=false;
      }
      this.generation=s.generation;
      const allowed=(s.permitted || []).filter(id=>id !== 'ch-video');
      for(const [id,entry] of this.parties)if(!allowed.includes(id)){await entry.room.disconnect();this.parties.delete(id);}
      for(const id of allowed){
        let entry=this.parties.get(id);
        if(entry && entry.room.state !== 'connected'){await entry.room.disconnect();this.parties.delete(id);entry=null;}
        if(!entry){
          const data=await this.token(id);if(data.generation !== s.generation)throw new Error('権限更新中です。再接続します');const room=new LivekitClient.Room({adaptiveStream:false,dynacast:false});entry={room,mic:null,io:new Map()};
          room.on(LivekitClient.RoomEvent.TrackSubscribed,(track,pub,participant)=>{
            if(track.kind !== LivekitClient.Track.Kind.Audio)return;
            const key=participant.identity+'::'+id+'::'+pub.trackSid;
            const call={stream:new MediaStream([track.mediaStreamTrack]),livekitTrack:track,trackName:pub.trackName,secureParty:id,secureSender:participant.identity,isIOTrack:pub.trackName.startsWith('io_'),isIOStereoTrack:false};
            state.mediaCalls[key]=call;setupPeerMixer(call);
          });
          room.on(LivekitClient.RoomEvent.TrackUnsubscribed,(_track,pub,participant)=>this.removeCall(participant.identity+'::'+id+'::'+pub.trackSid));
          room.on(LivekitClient.RoomEvent.Reconnecting,()=>yySafeTalkOff('音声再接続中',true));
          await room.connect(data.url,data.token);await room.startAudio();this.parties.set(id,entry);
        }
        await this.publishInto(id,entry);
      }
      this.mute();
    }finally{this.rotating=false;this.busy=false;}
  },
  async publishInto(id,entry){
    const channel=state.channels.find(c=>c.id===id);
    if(!state.isAdmin && channel?.type==='Listen')return;
    if(this.mic && this.mic.readyState==='live' && !entry.mic){
      const raw=this.mic.clone();raw.enabled=false;
      entry.mic=await entry.room.localParticipant.publishTrack(raw,{name:'mic',source:LivekitClient.Track.Source.Microphone});
    }
    for(const [name,item] of this.io){
      const target=state.ioBridge[item.assignment];
      const current=entry.io.get(name);
      if(current && (!state.isAdmin || target !== id || current.original !== item.raw)){
        await entry.room.localParticipant.unpublishTrack(current.pub.track);current.pub.track.stop();entry.io.delete(name);
      }
      if(state.isAdmin && target===id && !entry.io.has(name)){
        const raw=item.raw.clone();const pub=await entry.room.localParticipant.publishTrack(raw,{name,source:LivekitClient.Track.Source.Microphone,audioPreset:{maxBitrate:26000,priority:'high'},dtx:false,red:false});
        entry.io.set(name,{pub,original:item.raw});
      }
    }
  },
  mute(){
    for(const [id,entry] of this.parties)if(entry.mic?.track?.mediaStreamTrack)entry.mic.track.mediaStreamTrack.enabled=this.mic?.readyState === 'live' && state.talkStates[id] === true && !state.isMasterMicMuted && !state.ioBridge.enabled;
  },
  async publishMic(raw){
    this.mic=raw;
    for(const entry of this.parties.values())if(entry.mic){await entry.room.localParticipant.unpublishTrack(entry.mic.track);entry.mic.track.stop();entry.mic=null;}
    await this.reconcile();
    const virtual={mediaStreamTrack:raw,sid:'party-microphones',stop:()=>{raw.stop();this.mute();},replaceTrack:async fresh=>{raw.stop();await this.publishMic(fresh);virtual.mediaStreamTrack=fresh;}};
    return {track:virtual};
  },
  async publishIO(raw,name){
    if(!state.isAdmin)throw new Error('管理者権限が必要です');
    const kind=name==='io_4w_stereo'?'4w':'pgm',ctx=state.audioCtx;
    const source=ctx.createMediaStreamSource(new MediaStream([raw])),split=ctx.createChannelSplitter(2);source.connect(split);
    const destinations=[];
    for(const [side,index] of [['l',0],['r',1]]){
      const dest=ctx.createMediaStreamDestination();split.connect(dest,index);destinations.push(dest);
      const key='io_'+kind+'_'+side;this.io.set(key,{raw:dest.stream.getAudioTracks()[0],assignment:'inAssign'+(kind==='4w'?'4w':'Pgm')+side.toUpperCase()});
    }
    await this.reconcile();
    return {track:{mediaStreamTrack:raw,sid:name,stop:()=>{
      source.disconnect();split.disconnect();for(const dest of destinations)dest.stream.getTracks().forEach(t=>t.stop());
      for(const side of ['l','r'])this.io.delete('io_'+kind+'_'+side);
      for(const entry of this.parties.values())for(const [key,item] of entry.io)if(key.startsWith('io_'+kind+'_')){entry.room.localParticipant.unpublishTrack(item.pub.track).catch(()=>{});item.pub.track.stop();entry.io.delete(key);}
    }}};
  }
};
window.addEventListener('pagehide',()=>security.stop());
