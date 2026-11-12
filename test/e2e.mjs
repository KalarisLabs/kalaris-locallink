// End-to-end protocol test: starts a mock backend and a bridge, then acts as a browser.
// node test/e2e.mjs
import { spawn } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import http from 'node:http';

const here = path.dirname(fileURLToPath(import.meta.url));
const PORT = 7499, BACKEND = 9919;
const B = `http://127.0.0.1:${PORT}`;
const SITE = 'https://chat.example', OTHER = 'https://evil.example';
const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'locallink-test-'));

let out = '';
const procs = [
  spawn(process.execPath, [path.join(here, 'mock-backend.mjs'), BACKEND]),
  spawn(process.execPath, [path.join(here, '../bridge/locallink-bridge.mjs'), '--port', PORT, '--no-open', '--data-dir', dataDir, '--backend', `mock=http://127.0.0.1:${BACKEND}`, '--backend', 'down=http://127.0.0.1:9'], { stdio: ['ignore', 'pipe', 'inherit'] }),
];
procs[1].stdout.on('data', d => out += d);
const cleanup = () => { procs.forEach(p => p.kill()); fs.rmSync(dataDir, { recursive: true, force: true }); };

let passed = 0, failed = 0;
const check = (name, ok, detail = '') => { ok ? passed++ : failed++; console.log(`${ok ? 'ok  ' : 'FAIL'} ${name}${ok ? '' : '  ' + detail}`); };
const req = (p, { origin = SITE, token, method = 'GET', body, headers = {} } = {}) => fetch(B + p, {
  method, redirect: 'manual',
  headers: { ...(origin && { Origin: origin }), ...(token && { Authorization: `Bearer ${token}` }), ...(body && typeof body === 'object' && { 'Content-Type': 'application/json' }), ...headers },
  body: body && (typeof body === 'object' ? JSON.stringify(body) : body),
});
const code = async r => (await r.json()).error?.code;
const approvalSecret = () => [...out.matchAll(/approve\?k=([\w-]+)/g)].at(-1)[1];
const form = (fields, origin = B) => req('/approve', { method: 'POST', origin, body: new URLSearchParams(fields).toString(), headers: { 'Content-Type': 'application/x-www-form-urlencoded' } });
// Raw request so we can send a Host header fetch() would not let us set.
const rawHost = host => new Promise(resolve => http.get({ host: '127.0.0.1', port: PORT, path: '/.well-known/locallink', headers: { Host: host } }, r => resolve(r.statusCode)));

try {
  for (let i = 0; i < 50 && !out.includes('listening'); i++) await new Promise(r => setTimeout(r, 100));
  await new Promise(r => setTimeout(r, 300));

  // Discovery
  let r = await req('/.well-known/locallink');
  let j = await r.json();
  check('discovery responds', r.status === 200 && j.protocol === 'locallink' && j.version === '0.1');
  check('discovery reveals no models', !JSON.stringify(j).includes('echo'));
  check('CORS echoes origin', r.headers.get('access-control-allow-origin') === SITE);
  r = await req('/locallink/v1/models', { method: 'OPTIONS' });
  check('preflight allows private network', r.status === 204 && r.headers.get('access-control-allow-private-network') === 'true');
  check('DNS-rebinding Host is rejected', await rawHost('attacker.example') === 403);

  // Unauthenticated access
  check('models need a token', (await req('/locallink/v1/models')).status === 401);
  check('chat needs a token', (await req('/locallink/v1/chat/completions', { method: 'POST', body: { model: 'mock/echo-small', messages: [] } })).status === 401);

  // Pairing rules
  check('pair refuses missing origin', await code(await req('/locallink/v1/pair', { method: 'POST', origin: null, body: {} })) === 'origin_not_allowed');
  check('pair refuses http origin', await code(await req('/locallink/v1/pair', { method: 'POST', origin: 'http://chat.example', body: {} })) === 'origin_not_allowed');
  r = await req('/locallink/v1/pair', { method: 'POST', body: { app_name: '<b>Chat</b>' } });
  const pair = await r.json();
  check('pair creates a request', r.status === 201 && /^\d{3}-\d{3}$/.test(pair.code) && pair.request_id.startsWith('pr_'));
  check('second pair from same origin is refused', await code(await req('/locallink/v1/pair', { method: 'POST', body: {} })) === 'pair_pending');
  check('poll is pending', (await (await req(`/locallink/v1/pair/${pair.request_id}`)).json()).status === 'pending');
  check('another origin cannot poll it', (await (await req(`/locallink/v1/pair/${pair.request_id}`, { origin: OTHER })).json()).status === 'expired');

  // Approval page
  const k = approvalSecret();
  check('request_id cannot open approval page', (await req(`/approve?k=${pair.request_id}`, { origin: null })).status === 404);
  r = await req(`/approve?k=${k}`, { origin: null });
  const html = await r.text();
  check('approval page shows origin, code and models', html.includes(SITE) && html.includes(pair.code) && html.includes('mock/echo-small') && html.includes('mock/echo-large'));
  check('approval page escapes app name', !html.includes('<b>Chat</b>') && html.includes('&lt;b&gt;Chat'));
  check('approval page forbids framing, has no CORS', r.headers.get('x-frame-options') === 'DENY' && !r.headers.get('access-control-allow-origin'));
  check('site cannot approve itself (cross-origin POST)', (await form({ k, decision: 'allow', future: '1' }, SITE)).status === 403);
  check('still pending after forged approval', (await (await req(`/locallink/v1/pair/${pair.request_id}`)).json()).status === 'pending');
  check('user approval succeeds', (await form({ k, decision: 'allow', model: 'mock/echo-small' })).status === 200);

  j = await (await req(`/locallink/v1/pair/${pair.request_id}`)).json();
  const token = j.token;
  check('poll returns a token', j.status === 'approved' && token?.startsWith('ll_'));
  check('token is handed out once', (await (await req(`/locallink/v1/pair/${pair.request_id}`)).json()).status === 'expired');
  check('token is stored hashed', !fs.readFileSync(path.join(dataDir, 'grants.json'), 'utf8').includes(token));

  // Using the grant
  j = await (await req('/locallink/v1/session', { token })).json();
  check('session describes the grant', j.origin === SITE && j.models.length === 1);
  j = await (await req('/locallink/v1/models', { token })).json();
  check('models lists only granted models', j.data.length === 1 && j.data[0].id === 'mock/echo-small' && j.data[0].backend === 'mock');
  check('token fails from another origin', (await req('/locallink/v1/models', { token, origin: OTHER })).status === 401);
  check('ungranted model is refused', await code(await req('/locallink/v1/chat/completions', { method: 'POST', token, body: { model: 'mock/echo-large', messages: [] } })) === 'model_not_allowed');
  check('model outside the grant on an unknown backend is refused',await code(await req('/locallink/v1/chat/completions', { method: 'POST', token, body: { model: 'nope/x', messages: [] } })) === 'model_not_allowed');
  check('bad JSON is 400', await code(await req('/locallink/v1/chat/completions', { method: 'POST', token, body: '{nope', headers: { 'Content-Type': 'application/json' } })) === 'bad_request');

  r = await req('/locallink/v1/chat/completions', { method: 'POST', token, body: { model: 'mock/echo-small', messages: [{ role: 'user', content: 'hello there' }] } });
  j = await r.json();
  check('non-streaming chat works, model id rewritten', j.choices[0].message.content === '[echo-small] You said: hello there');
  r = await req('/locallink/v1/chat/completions', { method: 'POST', token, body: { model: 'mock/echo-small', stream: true, messages: [{ role: 'user', content: 'stream me' }] } });
  const sse = await r.text();
  const text = sse.split('\n').filter(l => l.startsWith('data: {')).map(l => JSON.parse(l.slice(6)).choices[0].delta.content).join('');
  check('streaming chat works', r.headers.get('content-type').includes('text/event-stream') && text === '[echo-small] You said: stream me' && sse.includes('[DONE]'));

  // Deny + cooldown, from a second origin
  r = await req('/locallink/v1/pair', { method: 'POST', origin: OTHER, body: {} });
  const p2 = await r.json();
  await form({ k: approvalSecret(), decision: 'deny' });
  check('denied request reports denied', (await (await req(`/locallink/v1/pair/${p2.request_id}`, { origin: OTHER })).json()).status === 'denied');
  check('denied origin is in cooldown', await code(await req('/locallink/v1/pair', { method: 'POST', origin: OTHER, body: {} })) === 'pair_cooldown');

  // "All models" grant reaches a dead backend
  r = await req('/locallink/v1/pair', { method: 'POST', origin: 'http://localhost:3000', body: {} });
  const p3 = await r.json();
  await form({ k: approvalSecret(), decision: 'allow', future: '1' });
  const t3 = (await (await req(`/locallink/v1/pair/${p3.request_id}`, { origin: 'http://localhost:3000' })).json()).token;
  check('http://localhost origin can pair; "all" grant lists both models', (await (await req('/locallink/v1/models', { token: t3, origin: 'http://localhost:3000' })).json()).data.length === 2);
  check('dead backend is 502', await code(await req('/locallink/v1/chat/completions', { method: 'POST', token: t3, origin: 'http://localhost:3000', body: { model: 'down/x', messages: [] } })) === 'backend_unavailable');

  // Revocation
  check('site can revoke itself', (await req('/locallink/v1/session', { method: 'DELETE', token })).status === 204);
  check('revoked token stops working', (await req('/locallink/v1/models', { token })).status === 401);
} catch (e) {
  failed++; console.error('Test crashed:', e);
} finally {
  cleanup();
}
console.log(`\n${passed} passed, ${failed} failed`);
process.exit(failed ? 1 : 0);
