import fs from 'node:fs/promises';
import vm from 'node:vm';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
const base=new URL('../',import.meta.url);
const build=spawnSync('python3',[new URL('scripts/build.py',base).pathname],{encoding:'utf8'});
assert.equal(build.status,0,build.stderr);
const html=await fs.readFile(new URL('public/index.html',base),'utf8');
for(const m of html.matchAll(/<script\b[^>]*>([\s\S]*?)<\/script>/g))if(m[1].trim())new vm.Script(m[1]);
assert.doesNotMatch(html,/mqtt\.connect|publishData\(|WORKER_AUTH_URL|管理者パスワード/);
const config=await fs.readFile(new URL('wrangler.toml',base),'utf8');
assert.match(config,/workers_dev = false/);assert.match(config,/preview_urls = false/);assert.match(config,/run_worker_first = true/);assert.match(config,/directory = "\.\/public"/);
assert.deepEqual(await fs.readdir(new URL('public/',base)),['index.html']);
console.log('Build, inline JavaScript syntax, asset allowlist and development routing checks passed.');
for(const dir of ['app','public','src','test']){
  for(const filename of await fs.readdir(new URL(dir+'/',base))){
    const content=await fs.readFile(new URL(dir+'/'+filename,base),'utf8');
    assert.doesNotMatch(content,/pass\s*!==\s*["'][^"']+["']/,`Embedded administrator credential: ${dir}/${filename}`);
    assert.doesNotMatch(content,/-----BEGIN (?:RSA |EC )?PRIVATE KEY-----\r?\n[A-Za-z0-9+/=]+\r?\n/,`PEM credential: ${dir}/${filename}`);
    for(const match of content.matchAll(/(?:LIVEKIT_API_SECRET|GOOGLE_SERVICE_ACCOUNT_PRIVATE_KEY)\s*[:=]\s*["']([^"']+)["']/g))assert.match(match[1],/^test-only-/,`Literal credential: ${dir}/${filename}`);
  }
}
console.log('Checked for embedded administrator passwords and literal server credentials.');
