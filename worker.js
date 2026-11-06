import { authenticate, verifyAccess, resolveDirectoryUser, HttpError, fail } from './src/auth.js';
import { roomPolicy, validId } from './src/room.js';
export { RoomCoordinator } from './src/room.js';

const headers = {
  'Cache-Control':'private, no-store, max-age=0', 'Pragma':'no-cache', 'X-Content-Type-Options':'nosniff',
  'Referrer-Policy':'no-referrer', 'X-Frame-Options':'DENY',
  'Permissions-Policy':'camera=(self), microphone=(self), geolocation=()',
  'Content-Security-Policy': "default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://unpkg.com; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://cdnjs.cloudflare.com; font-src https://fonts.gstatic.com https://cdnjs.cloudflare.com; img-src 'self' data: blob:; media-src 'self' data: blob:; connect-src 'self' https://*.livekit.cloud wss://*.livekit.cloud; worker-src 'self' blob:; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'"
};

export async function route(request,env,actor) {
  const url = new URL(request.url);
  if(url.pathname === '/api/session' && request.method === 'GET')return Response.json({identity:actor.identity,admin:actor.admin,email:actor.email});
  if(url.pathname === '/api/directory' && request.method === 'GET'){if(!actor.admin)fail(403,'Administrator required');return Response.json(await resolveDirectoryUser(url.searchParams.get('email'),env));}
  const match = url.pathname.match(/^\/api\/rooms\/([^/]+)\/(state|events|token|socket)$/);
  if(match){
    const room=decodeURIComponent(match[1]);if(!validId(room))fail(400,'Invalid room');roomPolicy(env,room,actor);
    const action=match[2] === 'events'?'event':match[2];
    if(action === 'socket'){
      if(request.method !== 'GET' || request.headers.get('Upgrade')?.toLowerCase() !== 'websocket')fail(400,'WebSocket required');
      return env.ROOMS.get(env.ROOMS.idFromName(room)).fetch(new Request('https://room.internal/',{headers:{Upgrade:'websocket','X-YY-Actor':JSON.stringify(actor),'X-YY-Room':room}}));
    }
    if(request.method !== (action === 'state'?'GET':'POST'))fail(405,'Method not allowed');
    let payload;
    if(request.method === 'POST'){
      if(request.headers.get('Content-Type')?.split(';')[0].trim() !== 'application/json')fail(415,'JSON required');
      payload=await readJson(request,32768);
    }
    return env.ROOMS.get(env.ROOMS.idFromName(room)).fetch(new Request('https://room.internal/',{method:'POST',body:JSON.stringify({actor,room,action,payload})}));
  }
  if(url.pathname.startsWith('/api/'))fail(404,'Not found');
  if(!['GET','HEAD'].includes(request.method))fail(405,'Method not allowed');
  if(!['/','/index.html'].includes(url.pathname))fail(404,'Not found');
  return env.ASSETS.fetch(request);
}
export default {
  async fetch(request,env){
    let response;
    try{
      const url=new URL(request.url);
      if(!env.APP_ORIGIN || url.origin !== env.APP_ORIGIN || url.protocol !== 'https:')fail(403,'Host not allowed');
      const origin=request.headers.get('Origin');
      if((origin && origin !== env.APP_ORIGIN) || request.headers.get('Sec-Fetch-Site') === 'cross-site')fail(403,'Origin not allowed');
      if(url.pathname === '/api/bridge/tally'){
        if(request.method !== 'POST' || !env.TALLY_AUD || !env.TALLY_ROOM)fail(403,'Tally bridge not configured');
        await verifyAccess(request.headers.get('Cf-Access-Jwt-Assertion'),{...env,ACCESS_AUD:env.TALLY_AUD},fetch,'tally');
        if(request.headers.get('Content-Type') !== 'application/json')fail(415,'JSON required');
        const payload=await readJson(request,1024);
        if(payload?.type !== 'tally')fail(403,'Tally only');
        response=await env.ROOMS.get(env.ROOMS.idFromName(env.TALLY_ROOM)).fetch(new Request('https://room.internal/',{method:'POST',body:JSON.stringify({actor:{id:'tally_bridge',identity:'u_tally_bridge',admin:false,kind:'tally'},room:env.TALLY_ROOM,action:'event',payload})}));
      }else{const actor=await authenticate(request,env);response=await route(request,env,actor);}
    }catch(e){response=Response.json({error:e instanceof HttpError?e.message:'Service unavailable'},{status:e.status || 503});}
    if(response.status === 101)return response;
    const result=new Response(response.body,response);for(const [k,v] of Object.entries(headers))result.headers.set(k,v);return result;
  }
};

async function readJson(request,limit){
  const reader=request.body?.getReader();let size=0;const chunks=[];if(!reader)fail(400,'Body required');
  while(true){const {done,value}=await reader.read();if(done)break;size+=value.length;if(size>limit){await reader.cancel();fail(413,'Request too large');}chunks.push(value);}
  const data=new Uint8Array(size);let offset=0;for(const chunk of chunks){data.set(chunk,offset);offset+=chunk.length;}
  try{return JSON.parse(new TextDecoder().decode(data));}catch{fail(400,'Invalid JSON');}
}
