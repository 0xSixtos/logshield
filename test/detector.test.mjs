import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { analyze, redact, MAX_BYTES, MAX_FINDINGS } from '../dist/detector.js';

const clean = (text, options) => { const result=analyze(text,options); return { ...result, output:redact(text,result.findings) }; };

test('redacts named credentials while retaining surrounding text',()=>{
  const text='INFO password=fictional-password api_key=fictional-key user=demo';
  const r=clean(text); assert.equal(r.findings.length,2); assert.equal(r.output,'INFO password=[REDACTED:PASSWORD] api_key=[REDACTED:API_KEY] user=demo');
});
test('redacts quoted .env values with spaces and escaped quotes',()=>{
  const text=String.raw`PASSWORD="a long \"fictional\" secret"`;
  assert.equal(clean(text).output,'PASSWORD="[REDACTED:PASSWORD]"');
});
test('JSON stays valid and retains exact non-sensitive formatting',()=>{
  const text='{\n  "user": {"password": "fake\\\"password", "name": "Alex"},\n  "ok": true\n}';
  const r=clean(text); assert.equal(r.format,'json'); assert.equal(JSON.parse(r.output).user.password,'[REDACTED:PASSWORD]');
  assert.equal(r.output,'{\n  "user": {"password": "[REDACTED:PASSWORD]", "name": "Alex"},\n  "ok": true\n}');
});
test('JSON redacts numeric, array and object secrets without corrupting syntax',()=>{
  const text='{"token":12345,"secret":{"nested":"fake"},"password":["one","two"],"ok":3}';
  const r=clean(text); const value=JSON.parse(r.output);
  assert.equal(value.token,'[REDACTED:TOKEN]'); assert.equal(value.secret,'[REDACTED:API_KEY]');assert.equal(value.password,'[REDACTED:PASSWORD]');assert.equal(value.ok,3);
});
test('handles duplicate JSON keys without losing their positions',()=>{
  const r=clean('{"password":"first","password":"second"}');assert.equal(r.findings.length,2);assert.ok(!r.output.includes('first'));assert.ok(!r.output.includes('second'));assert.doesNotThrow(()=>JSON.parse(r.output));
});
test('handles top-level JSON arrays and nested credentials',()=>{
  const r=clean('[{"API_KEY":"example"},{"refresh_token":"example2"}]');assert.equal(r.findings.length,2);assert.doesNotThrow(()=>JSON.parse(r.output));
});
test('does not treat counts and public identifiers as credential field names',()=>{
  assert.equal(clean('{"tokenCount":42,"publicKey":"example","clientId":"demo","password":null}').findings.length,0);
});
test('redacts emails and allows explicit opt-out',()=>{
  const text='Contact alex@example.com or support@example.org';assert.equal(clean(text).findings.length,2);assert.equal(clean(text,{EMAIL:false}).output,text);
});
test('email redaction retains plain-text log field names',()=>{
  assert.equal(clean('contact=alex@example.com').output,'contact=[REDACTED:EMAIL]');
});
test('IP detection is off by default and excludes invalid octets',()=>{
  const text='host=192.168.1.12 bad=999.1.2.3';assert.equal(clean(text).findings.length,0);assert.equal(clean(text,{IP_ADDRESS:true}).output,'host=[REDACTED:IP_ADDRESS] bad=999.1.2.3');
});
test('redacts provider-prefixed tokens',()=>{
  const r=clean('key: ghp_'+ 'a'.repeat(36)+' and AKIA'+'A'.repeat(16));assert.equal(r.findings.length,2);assert.ok(!r.output.includes('ghp_'));assert.ok(!r.output.includes('AKIA'));
});
test('redacts standalone JWT-shaped strings',()=>{
  const r=clean('Received eyJleGFtcGxlIjp0cnVlfQ.ZmljdGlvbmFs.c2lnbmF0dXJl');assert.equal(r.findings[0].type,'TOKEN');assert.equal(r.output,'Received [REDACTED:TOKEN]');
});
test('authorization header covers complete Bearer and Basic credentials',()=>{
  const r=clean('Authorization: Bearer fictional_token_123\nProxy-Authorization: Basic ZGVtbzpmaWN0aW9uYWw=\nAccept: application/json');assert.equal(r.findings.length,2);assert.ok(!r.output.includes('fictional_token_123'));assert.ok(!r.output.includes('ZGVtb'));assert.ok(r.output.includes('Accept: application/json'));
});
test('cookie headers cover multiple cookie pairs',()=>{
  const r=clean('Cookie: sid=fictional; auth=example; name=demo\r\nX-Test: yes');assert.equal(r.output,'Cookie: [REDACTED:COOKIE]\r\nX-Test: yes');
});
test('JSON authorization redaction remains valid JSON',()=>{
  const r=clean('{"Authorization":"Bearer fictional-secret-123","count":12}');assert.deepEqual(JSON.parse(r.output),{Authorization:'[REDACTED:AUTH]',count:12});assert.equal(r.findings.length,1);
});
test('URL userinfo is redacted without removing host and path',()=>{
  const r=clean('https://demo:fictional-password@db.example.com:443/path');assert.equal(r.output,'https://[REDACTED:CREDENTIALS]@db.example.com:443/path');
});
test('sensitive URL query values are redacted independently',()=>{
  const r=clean('https://example.com/?token=fake&api_key=fake2&limit=5');assert.equal(r.output,'https://example.com/?token=[REDACTED:TOKEN]&api_key=[REDACTED:API_KEY]&limit=5');
});
test('multiline private key is one finding',()=>{
  const input='prefix\n-----BEGIN PRIVATE KEY-----\nnot-a-real-key\n-----END PRIVATE KEY-----\nsuffix';const r=clean(input);assert.equal(r.findings.length,1);assert.equal(r.findings[0].type,'PRIVATE_KEY');assert.equal(r.output,'prefix\n[REDACTED:PRIVATE_KEY]\nsuffix');
});
test('overlapping token, email and named-field matches never leak partial values',()=>{
  const r=clean('{"password":"alex@example.com","api_key":"ghp_'+ 'a'.repeat(36)+'"}');assert.equal(r.findings.length,2);assert.ok(!r.output.includes('alex'));assert.ok(!r.output.includes('ghp_'));
});
test('opt-out restores only the selected original range',()=>{
  const text='password=first token=second';const r=analyze(text);const selected=new Set([r.findings[0].id]);assert.equal(redact(text,r.findings,selected),'password=[REDACTED:PASSWORD] token=second');assert.equal(text,'password=first token=second');
});
test('UTF-16 offsets and line/column handling preserve emoji and CRLF',()=>{
  const text='🛡️ demo\r\npassword=fake\r\nend';const r=clean(text);assert.equal(r.findings[0].line,2);assert.equal(r.findings[0].column,10);assert.equal(r.output,'🛡️ demo\r\npassword=[REDACTED:PASSWORD]\r\nend');
});
test('invalid JSON falls back to text with an explicit diagnostic',()=>{
  const r=clean('{"password":"fake",}');assert.equal(r.invalidJson,true);assert.equal(r.format,'text');assert.ok(!r.output.includes('fake'));
});
test('empty inputs are accepted without invented findings',()=>{const r=clean('');assert.equal(r.findings.length,0);assert.equal(r.output,'');});
test('rejects oversized input based on UTF-8 bytes',()=>{assert.throws(()=>analyze('a'.repeat(MAX_BYTES+1)),/FILE_TOO_LARGE/);assert.throws(()=>analyze('😀'.repeat(MAX_BYTES/4+1)),/FILE_TOO_LARGE/);});
test('signals truncation instead of silently treating an incomplete scan as complete',()=>{
  const r=analyze(Array.from({length:MAX_FINDINGS+2},(_,i)=>`password=fictional${i}`).join('\n'));assert.equal(r.truncated,true);assert.equal(r.findings.length,MAX_FINDINGS);
});
test('every finding is in bounds and output agrees over many synthetic JSON cases',()=>{
  for(let i=0;i<75;i++){
    const text=JSON.stringify({label:`🛡️${i}`,password:`fictional-${i}-\\-\"`,nested:[{email:`u${i}@example.com`,token:`demo${i}`}]},null,i%4);
    const r=clean(text);assert.equal(r.findings.length,3);const parsed=JSON.parse(r.output);assert.equal(parsed.password,'[REDACTED:PASSWORD]');assert.equal(parsed.label,`🛡️${i}`);
    let end=0;for(const f of r.findings){assert.ok(f.start>=end&&f.end<=text.length);end=f.end;}
  }
});
test('redaction rejects overlapping or out-of-range findings',()=>{
  assert.throws(()=>redact('abc',[{id:'x',start:0,end:9,replacement:'x'}]),/Invalid finding/);
});
test('browser app forbids outbound connections and renders logs using text nodes',async()=>{
  const html=await readFile(new URL('../dist/index.html',import.meta.url),'utf8');const app=await readFile(new URL('../dist/app.js',import.meta.url),'utf8');
  assert.match(html,/connect-src 'none'/);assert.match(html,/object-src 'none'/);assert.doesNotMatch(app,/\b(?:fetch|XMLHttpRequest|WebSocket|localStorage|sessionStorage)\b/);assert.match(app,/document.createTextNode\(original.slice/);
});
