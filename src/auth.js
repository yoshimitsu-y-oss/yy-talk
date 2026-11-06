export class HttpError extends Error {
  constructor(status, message) { super(message); this.status = status; }
}
export const fail = (status, message) => { throw new HttpError(status, message); };
export const encode = value => btoa(String.fromCharCode(...new Uint8Array(value))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
export const bytes = value => Uint8Array.from(atob(value.replace(/-/g, '+').replace(/_/g, '/')), c => c.charCodeAt(0));
const utf8 = value => new TextEncoder().encode(value);
const json64 = value => encode(utf8(JSON.stringify(value)));

export async function signHmac(payload, secret) {
  const data = `${json64({ alg: 'HS256', typ: 'JWT' })}.${json64(payload)}`;
  const key = await crypto.subtle.importKey('raw', utf8(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  return `${data}.${encode(await crypto.subtle.sign('HMAC', key, utf8(data)))}`;
}

const jwksCache = new Map();
async function getJwks(issuer, fetcher, refresh) {
  let entry = jwksCache.get(issuer);
  if (!entry || entry.until < Date.now() || refresh) {
    const r = await fetcher(`${issuer}/cdn-cgi/access/certs`, { redirect: 'error', signal: AbortSignal.timeout(5000) });
    if (!r.ok) fail(503, 'Identity verification unavailable');
    entry = { keys: (await r.json()).keys, until: Date.now() + 300000 };
    if (!Array.isArray(entry.keys)) fail(503, 'Identity verification unavailable');
    jwksCache.set(issuer, entry);
  }
  return entry.keys;
}

export async function verifyAccess(token, env, fetcher = fetch, mode = 'human') {
  const issuer = env.ACCESS_ISSUER;
  if (!/^https:\/\/[a-z0-9-]+\.cloudflareaccess\.com$/.test(issuer || '') || !env.ACCESS_AUD) fail(503, 'Access not configured');
  if (!token || token.length > 16384) fail(401, 'Authentication required');
  try {
    const parts = token.split('.');
    if (parts.length !== 3) fail(401, 'Invalid identity');
    const header = JSON.parse(new TextDecoder().decode(bytes(parts[0])));
    const claims = JSON.parse(new TextDecoder().decode(bytes(parts[1])));
    if (header.alg !== 'RS256' || typeof header.kid !== 'string') fail(401, 'Invalid identity');
    let keys = await getJwks(issuer, fetcher, false);
    if (!keys.some(k => k.kid === header.kid)) keys = await getJwks(issuer, fetcher, true);
    const jwk = keys.find(k => k.kid === header.kid && k.kty === 'RSA' && (!k.alg || k.alg === 'RS256') && (!k.use || k.use === 'sig'));
    if (!jwk) fail(401, 'Invalid identity');
    const key = await crypto.subtle.importKey('jwk', jwk, { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, false, ['verify']);
    if (!await crypto.subtle.verify('RSASSA-PKCS1-v1_5', key, bytes(parts[2]), utf8(`${parts[0]}.${parts[1]}`))) fail(401, 'Invalid identity');
    const now = Math.floor(Date.now() / 1000);
    if (claims.iss !== issuer || !(Array.isArray(claims.aud) ? claims.aud : [claims.aud]).includes(env.ACCESS_AUD)
      || !Number.isFinite(claims.exp) || claims.exp <= now || !Number.isFinite(claims.iat) || claims.iat > now + 30
      || (claims.nbf !== undefined && (!Number.isFinite(claims.nbf) || claims.nbf > now + 30))
      || typeof claims.sub !== 'string' || !claims.sub || claims.type !== 'app'
      || (mode === 'human' && (typeof claims.email !== 'string' || !/^[a-zA-Z0-9._+%-]+@[a-zA-Z0-9.-]+$/.test(claims.email)))
      || (mode === 'tally' && (!env.TALLY_SERVICE_TOKEN_ID || claims.common_name !== env.TALLY_SERVICE_TOKEN_ID))) fail(401, 'Invalid identity');
    return claims;
  } catch (e) { if (e instanceof HttpError) throw e; fail(401, 'Invalid identity'); }
}

let serviceToken;
async function directoryToken(env, fetcher) {
  // No credential values are logged or returned. Token cache is scoped to the delegation configuration.
  const scopeKey = `${env.GOOGLE_SERVICE_ACCOUNT_EMAIL}|${env.GOOGLE_DELEGATED_ADMIN}|${env.WORKSPACE_CUSTOMER_ID}`;
  if (serviceToken?.scopeKey === scopeKey && serviceToken.until > Date.now()) return serviceToken.token;
  const now = Math.floor(Date.now() / 1000);
  const payload = { iss: env.GOOGLE_SERVICE_ACCOUNT_EMAIL, sub: env.GOOGLE_DELEGATED_ADMIN,
    scope: 'https://www.googleapis.com/auth/admin.directory.user.readonly', aud: 'https://oauth2.googleapis.com/token', iat: now, exp: now + 300 };
  const pem = env.GOOGLE_SERVICE_ACCOUNT_PRIVATE_KEY.replace(/-----[^-]+-----/g, '').replace(/\s/g, '');
  const key = await crypto.subtle.importKey('pkcs8', bytes(pem), { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, false, ['sign']);
  const data = `${json64({ alg: 'RS256', typ: 'JWT' })}.${json64(payload)}`;
  const assertion = `${data}.${encode(await crypto.subtle.sign('RSASSA-PKCS1-v1_5', key, utf8(data)))}`;
  const r = await fetcher('https://oauth2.googleapis.com/token', { method: 'POST', redirect: 'error', signal: AbortSignal.timeout(5000),
    body: new URLSearchParams({ grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer', assertion }) });
  if (!r.ok) fail(503, 'Workspace verification unavailable');
  const body = await r.json();
  if (typeof body.access_token !== 'string') fail(503, 'Workspace verification unavailable');
  serviceToken = { scopeKey, token: body.access_token, until: Date.now() + Math.min(Number(body.expires_in) || 0, 240) * 1000 };
  return serviceToken.token;
}

export function validateWorkspaceUser(user, claims, env) {
  if (!user || user.customerId !== env.WORKSPACE_CUSTOMER_ID || user.suspended !== false || user.archived === true
    || typeof user.id !== 'string' || !/^[a-zA-Z0-9_-]{1,128}$/.test(user.id)
    || typeof user.primaryEmail !== 'string' || !/^[a-zA-Z0-9._+%-]+@[a-zA-Z0-9.-]+$/.test(user.primaryEmail)
    || ![user.primaryEmail, ...(user.aliases || [])].some(e => e.toLowerCase() === claims.email.toLowerCase())) fail(403, 'Active company account required');
  const admins = JSON.parse(env.ADMIN_DIRECTORY_IDS || '[]');
  return { id: user.id, identity: `u_${user.id}`, email: user.primaryEmail, admin: Array.isArray(admins) && admins.includes(user.id) };
}

const membershipCache = new Map();
export async function authenticate(request, env, fetcher = fetch) {
  const header = request.headers.get('Cf-Access-Jwt-Assertion');
  const cookie = request.headers.get('Cookie')?.match(/(?:^|;\s*)CF_Authorization=([^;]+)/)?.[1];
  const claims = await verifyAccess(header || cookie, env, fetcher);
  if (!env.WORKSPACE_CUSTOMER_ID || !env.GOOGLE_SERVICE_ACCOUNT_EMAIL || !env.GOOGLE_DELEGATED_ADMIN || !env.GOOGLE_SERVICE_ACCOUNT_PRIVATE_KEY) fail(503, 'Workspace not configured');
  const cacheKey = `${env.WORKSPACE_CUSTOMER_ID}|${claims.sub}|${claims.email}`;
  const cached = membershipCache.get(cacheKey);
  if (cached?.until > Date.now()) return validateWorkspaceUser(cached.user,claims,env);
  const token = await directoryToken(env, fetcher);
  const r = await fetcher(`https://admin.googleapis.com/admin/directory/v1/users/${encodeURIComponent(claims.email)}?projection=basic`, {
    headers: { Authorization: `Bearer ${token}` }, redirect: 'error', signal: AbortSignal.timeout(5000) });
  if (r.status === 404) fail(403, 'Active company account required');
  if (!r.ok) fail(503, 'Workspace verification unavailable');
  const user=await r.json();const actor=validateWorkspaceUser(user,claims,env);
  if(membershipCache.size >= 256)membershipCache.delete(membershipCache.keys().next().value);
  membershipCache.set(cacheKey,{user,until:Date.now()+15000});return actor;
}

export async function resolveDirectoryUser(email,env,fetcher=fetch){
  if(typeof email !== 'string' || !/^[a-zA-Z0-9._+%-]+@[a-zA-Z0-9.-]+$/.test(email))fail(400,'会社メールアドレスを入力してください');
  const token=await directoryToken(env,fetcher);
  const r=await fetcher(`https://admin.googleapis.com/admin/directory/v1/users/${encodeURIComponent(email)}?projection=basic`,{headers:{Authorization:`Bearer ${token}`},redirect:'error',signal:AbortSignal.timeout(5000)});
  if(r.status === 404)fail(403,'Active company account required');if(!r.ok)fail(503,'Workspace verification unavailable');
  const actor=validateWorkspaceUser(await r.json(),{email},env);return {identity:actor.identity,email:actor.email};
}
