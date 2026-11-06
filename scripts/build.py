from pathlib import Path
import re
root=Path(__file__).resolve().parents[1]
s=(root/'app/v56.html').read_text()
s=s.replace('sortablejs@latest','sortablejs@1.15.6')
s=re.sub(r'  <script src="https://unpkg.com/mqtt/dist/mqtt.min.js"></script>','',s)
s=s.replace('    const LIVEKIT_WS_URL = "wss://yy-talk-pe8z9ycq.livekit.cloud";','    let LIVEKIT_WS_URL = "";')
s=s.replace('    const WORKER_AUTH_URL = "https://yy-talk.yoshimitsu-y.workers.dev";', (root/'src/client-security.js').read_text())
# Route every control mutation to the authenticated server; ignore LiveKit Data entirely.
a=s.index('    async function sendData(payload)');b=s.index('    function removeChannel',a)
s=s[:a]+'''    async function sendData(payload) { return security.send(payload); }

'''+s[b:]
a=s.index('          room.on(LivekitClient.RoomEvent.DataReceived');b=s.index('          try {',s.index('          });',a)+14)
s=s[:a]+'''          // LiveKit Data is untrusted and never controls application state.

'''+s[b:]
# Eliminate public-broker presence and the local debug authorization path.
a=s.index("      if (myName.toLowerCase() !== 'debug') {");b=s.index("      if (isAdmin) { document.querySelectorAll",a);s=s[:a]+s[b:]
a=s.index("          if (myName.toLowerCase() === 'debug') {");b=s.index('          let token = "";',a);s=s[:a]+s[b:]
s=s.replace('      joinAudioPromise = activateAudioForJoin({ forceNewStream: false, showFallback: true });','      // JOIN audio was activated before the authentication request.')
# Verified identity and role replace arbitrary USER ID and administrator toggle.
a=s.index("      const rawRoomId = $('host-id')");b=s.index('      const btn = isAdmin',a)
s=s[:a]+'''      const rawRoomId = $('host-id')?.value.trim();
      if (!isSafeIdentifier(rawRoomId,64)) { alert('ROOM NAMEを確認してください'); return; }
      joinAudioPromise=activateAudioForJoin({forceNewStream:false,showFallback:true});
      let session;
      try { session = await security.join(rawRoomId); }
      catch (e) { joinAudioPromise?.then(stream=>stream?.getTracks?.().forEach(t=>t.stop())); state.audioEnabled=false; alert(e.message); return; }
      const myName = session.identity; isAdmin = session.admin;
      if ($('join-userid')) { $('join-userid').value=session.email; $('join-userid').readOnly=true; }

'''+s[b:]
# Do not restore room authority from localStorage.
s=s.replace('      loadRoomState(state.roomId);','      security.applying=true; try { security.config=null; security.apply(security.latest); } finally { security.applying=false; }')
old='''await fetch(`${WORKER_AUTH_URL}/?room=${encodeURIComponent(rawRoomId)}&user=${encodeURIComponent(myName)}`, { cache: 'no-store' })'''
s=s.replace(old,"await fetch(security.path('token'), { method:'POST', credentials:'same-origin', cache:'no-store', headers:{'Content-Type':'application/json'}, body:JSON.stringify({party:'ch-video'}) })")
s=s.replace('const data = await res.json(); token = data.token;', 'const data = await res.json(); token = data.token; LIVEKIT_WS_URL=data.url;')
a=s.index("          const res = await fetch(`${WORKER_AUTH_URL}");b=s.index('          autoReconnectAttempts = 0;',a)
s=s[:a]+'''          const data = await security.token('ch-video');
          LIVEKIT_WS_URL=data.url;
          await state.room.connect(data.url,data.token);
          await security.reconcile();
'''+s[b:]
s=s.replace("      if (state.myUserId.toLowerCase() === 'debug' || autoReconnectTimer) return;",'      if (security.rotating || autoReconnectTimer) return;')
s=s.replace("              state.hasSuccessfullyConnected = true;", "              state.hasSuccessfullyConnected = true;\n              await security.reconcile(); security.start();")
# Publish microphone only in the authorized party rooms.
s=s.replace("state.room.localParticipant.publishTrack(clonedTrack, { name: 'mic', source: LivekitClient.Track.Source.Microphone })",'security.publishMic(clonedTrack)')
a=s.index('            const pub = await state.room.localParticipant.publishTrack(localTrack, {');b=s.index('            if (pub?.track)',a)
s=s[:a]+'''            const pub = await security.publishIO(inputRaw,name);
'''+s[b:]
# A received track belongs to exactly one server-authorized party. Preserve v56's output buses.
s=s.replace('      if (!state.audioCtx) return;\n\n      /* One party bus', '      security.mute();\n      if (!state.audioCtx) return;\n\n      /* One party bus')
s=s.replace('          /* v29: Stereo I/O uses', '''          if (callData.secureParty) {
              const gainKey={io_4w_l:'inGain4wL',io_4w_r:'inGain4wR',io_pgm_l:'inGainPgmL',io_pgm_r:'inGainPgmR'}[callData.trackName];
              const trim=gainKey ? (state.ioBridge[gainKey] ?? 1) : 1;
              const gains=callData.chGains || {};
              for (const ch of state.channels) if(gains[ch.id]) gains[ch.id].gain.gain.setTargetAtTime(ch.id===callData.secureParty ? trim : 0,state.audioCtx.currentTime,0.02);
              continue;
          }

          /* v29: Stereo I/O uses''')
s=s.replace('const callInfo = state.mediaCalls[uid];', 'const callInfo = state.mediaCalls[uid] || Object.values(state.mediaCalls).find(c=>c.secureSender===uid);')
# No main-room audio is permitted; only the party-room receiver constructs audio mixers.
s=s.replace("            if (track.kind === LivekitClient.Track.Kind.Audio) {", "            if (track.kind === LivekitClient.Track.Kind.Audio) { return; /* audio belongs to party rooms */")
# Persist quality changes on the server as well.
s=s.replace('state.videoQuality = e.target.value; saveRoomState();','state.videoQuality = e.target.value; saveRoomState(); sendData({type:"set-video-quality",value:state.videoQuality});')
a=s.index("      const btnAddUser = $('btn-add-user');");b=s.index("      container.querySelectorAll('.btn-delete-col')",a)
s=s[:a]+'''      const btnAddUser=$('btn-add-user');
      if(btnAddUser)btnAddUser.onclick=async e=>{
        e.preventDefault();e.stopPropagation();
        const email=prompt('登録するメンバーの会社メールアドレスを入力してください:')?.trim();if(!email)return;
        try{
          const user=await security.api('/api/directory?email='+encodeURIComponent(email));
          await sendData({type:'restore-user',identity:user.identity});
          await sendData({type:'assign-channels',targetUid:user.identity,channels:state.channels.map(c=>c.id)});
          yyJumpToNewPatchItem('user',user.identity);
        }catch(err){alert(err.message);}
      };

'''+s[b:]
s=s.replace('>${escapeHtml(uid)}</span>','>${escapeHtml(security.label(uid))}</span>')
assert 'WORKER_AUTH_URL'  not in s
assert 'broker.emqx.io' not in s
assert 'publishData(' not in s
(root/'public/index.html').write_text(s)
