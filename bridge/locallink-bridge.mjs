#!/usr/bin/env node
// LocalLink bridge — reference implementation of SPEC.md v0.1.
// Zero dependencies. Requires Node 18+.
//
//   node locallink-bridge.mjs                 start the bridge
//   node locallink-bridge.mjs grants          list sites that have access
//   node locallink-bridge.mjs revoke <origin> remove a site's access
//
// Options: --port <n>  --backend <name>=<url> (repeatable)  --no-open  --data-dir <path>

import http from 'node:http';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawn } from 'node:child_process';
import { Readable } from 'node:stream';

const VERSION = '0.1.0';
const PORTS = [7465, 7466, 7467];
const PAIR_TTL_MS = 120_000;
const DENY_COOLDOWN_MS = 30_000;
const MAX_PENDING = 5;
const MAX_BODY = 10 * 1024 * 1024;

const DEFAULT_BACKENDS = {
  ollama: 'http://127.0.0.1:11434',
  lmstudio: 'http://127.0.0.1:1234',
  llamacpp: 'http://127.0.0.1:8080',
  jan: 'http://127.0.0.1:1337',
};

// ---------- CLI ----------

const argv = process.argv.slice(2);
const opts = { port: null, open: true, dataDir: path.join(os.homedir(), '.locallink'), backends: {} };
const positional = [];
for (let i = 0; i < argv.length; i++) {
  const a = argv[i];
  if (a === '--port') opts.port = Number(argv[++i]);
  else if (a === '--no-open') opts.open = false;
  else if (a === '--data-dir') opts.dataDir = path.resolve(argv[++i]);
  else if (a === '--backend') {
    const [name, ...rest] = String(argv[++i]).split('=');
    const url = rest.join('=').replace(/\/+$/, '');
    if (!/^[a-z0-9_-]+$/i.test(name) || !/^https?:\/\//.test(url)) fail(`Bad --backend value. Use name=http://host:port`);
    opts.backends[name] = url;
  } else if (a === '--help' || a === '-h') {
    console.log(fs.readFileSync(new URL(import.meta.url), 'utf8').split('\n').slice(1, 10).map(l => l.replace(/^\/\/ ?/, '')).join('\n'));
    process.exit(0);
  } else if (a.startsWith('--')) fail(`Unknown option ${a}`);
  else positional.push(a);
}
const backends = Object.keys(opts.backends).length ? opts.backends : DEFAULT_BACKENDS;

function fail(msg) { console.error(msg); process.exit(1); }

// ---------- Grants (persisted) ----------

const grantsFile = path.join(opts.dataDir, 'grants.json');
const sha256 = s => crypto.createHash('sha256').update(s).digest('hex');

function loadGrants() {
  try { return JSON.parse(fs.readFileSync(grantsFile, 'utf8')); } catch { return []; }
}
function saveGrants(grants) {
  fs.mkdirSync(opts.dataDir, { recursive: true, mode: 0o700 });
  const tmp = grantsFile + '.tmp';
  fs.writeFileSync(tmp, JSON.stringify(grants, null, 2), { mode: 0o600 });
  fs.renameSync(tmp, grantsFile);
}

if (positional[0] === 'grants') {
  const grants = loadGrants();
  if (!grants.length) console.log('No sites have access.');
  for (const g of grants) console.log(`${g.origin}\n  models: ${g.models === 'all' ? 'all' : g.models.join(', ')}\n  since:  ${g.created}`);
  process.exit(0);
}
if (positional[0] === 'revoke') {
  const origin = positional[1];
  if (!origin) fail('Usage: revoke <origin>');
  const grants = loadGrants();
  const rest = grants.filter(g => g.origin !== origin);
  saveGrants(rest);
  console.log(rest.length < grants.length ? `Revoked ${origin}` : `No grant for ${origin}`);
  process.exit(0);
}
if (positional.length) fail(`Unknown command ${positional[0]}`);

// ---------- Pairing state (in memory) ----------

const pending = new Map();   // request_id -> { origin, appName, code, secret, expires, status, token }
const cooldown = new Map();  // origin -> timestamp until which pairing is refused

function sweep() {
  const now = Date.now();
  for (const [id, p] of pending) if (p.expires < now) pending.delete(id);
  for (const [o, t] of cooldown) if (t < now) cooldown.delete(o);
}

// ---------- Backends ----------

async function listModels() {
  const lists = await Promise.all(Object.entries(backends).map(async ([name, url]) => {
    try {
      const r = await fetch(`${url}/v1/models`, { signal: AbortSignal.timeout(1500) });
      if (!r.ok) return [];
      const body = await r.json();
      return (body.data || []).filter(m => m && typeof m.id === 'string')
        .map(m => ({ id: `${name}/${m.id}`, object: 'model', backend: name, name: m.id }));
    } catch { return []; }
  }));
  return lists.flat();
}

const allowed = (grant, id) => grant.models === 'all' || grant.models.includes(id);

// ---------- HTTP helpers ----------

class HttpError extends Error {
  constructor(status, code, message) { super(message); this.status = status; this.code = code; }
}

function secureOrigin(origin) {
  let u;
  try { u = new URL(origin); } catch { return false; }
  if (u.origin !== origin) return false;
  if (u.protocol === 'https:') return true;
  return u.protocol === 'http:' && (u.hostname === 'localhost' || u.hostname === '127.0.0.1' || u.hostname === '[::1]');
}

function cors(req, res) {
  const origin = req.headers.origin;
  if (origin) {
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Vary', 'Origin');
  }
}

function json(res, status, body) {
  res.writeHead(status, { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' });
  res.end(JSON.stringify(body));
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = []; let size = 0;
    req.on('data', c => {
      size += c.length;
      if (size > MAX_BODY) { reject(new HttpError(413, 'too_large', 'Request body is too large.')); req.destroy(); }
      else chunks.push(c);
    });
    req.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
    req.on('error', reject);
  });
}

async function readJson(req) {
  const text = await readBody(req);
  try { const v = JSON.parse(text || '{}'); if (v && typeof v === 'object') return v; } catch {}
  throw new HttpError(400, 'bad_request', 'Body must be a JSON object.');
}

function authenticate(req) {
  const m = /^Bearer (ll_[A-Za-z0-9_-]+)$/.exec(req.headers.authorization || '');
  const grant = m && loadGrants().find(g => g.hash === sha256(m[1]));
  if (!grant || grant.origin !== req.headers.origin) {
    throw new HttpError(401, 'invalid_token', 'Missing, revoked, or wrong-origin token. Pair again.');
  }
  return grant;
}

const esc = s => String(s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

function openInBrowser(url) {
  const [cmd, args] = process.platform === 'darwin' ? ['open', [url]]
    : process.platform === 'win32' ? ['cmd', ['/c', 'start', '', url]]
    : ['xdg-open', [url]];
  try { spawn(cmd, args, { stdio: 'ignore', detached: true }).on('error', () => {}).unref(); } catch {}
}

// ---------- Site endpoints ----------

async function handlePair(req, res) {
  const origin = req.headers.origin;
  if (!origin || !secureOrigin(origin)) {
    throw new HttpError(403, 'origin_not_allowed', 'Pairing needs an https:// origin (or http://localhost).');
  }
  sweep();
  if (cooldown.has(origin)) throw new HttpError(429, 'pair_cooldown', 'This site was just denied. Try again in a moment.');
  for (const p of pending.values()) {
    if (p.origin === origin && p.status === 'pending') throw new HttpError(429, 'pair_pending', 'A request from this site is already waiting for approval.');
  }
  if (pending.size >= MAX_PENDING) throw new HttpError(429, 'too_many_requests', 'Too many pairing requests are waiting.');

  const body = await readJson(req);
  const appName = typeof body.app_name === 'string' ? body.app_name.slice(0, 64) : '';
  const n = String(crypto.randomInt(0, 1_000_000)).padStart(6, '0');
  const id = 'pr_' + crypto.randomBytes(16).toString('hex');
  const p = {
    origin, appName, code: `${n.slice(0, 3)}-${n.slice(3)}`,
    secret: crypto.randomBytes(24).toString('base64url'),
    expires: Date.now() + PAIR_TTL_MS, status: 'pending', token: null,
  };
  pending.set(id, p);

  const url = `${selfOrigin}/approve?k=${p.secret}`;
  console.log(`\nPairing request from ${origin}  (code ${p.code})\n  Approve or deny: ${url}`);
  if (opts.open) openInBrowser(url);

  json(res, 201, { request_id: id, code: p.code, expires_in: PAIR_TTL_MS / 1000 });
}

function handlePairPoll(req, res, id) {
  sweep();
  const p = pending.get(id);
  if (!p || p.origin !== req.headers.origin) return json(res, 200, { status: 'expired' });
  if (p.status === 'approved') { pending.delete(id); return json(res, 200, { status: 'approved', token: p.token }); }
  if (p.status === 'denied') { pending.delete(id); return json(res, 200, { status: 'denied' }); }
  json(res, 200, { status: 'pending' });
}

async function handleChat(req, res, grant) {
  const body = await readJson(req);
  const model = body.model;
  if (typeof model !== 'string' || !model.includes('/')) throw new HttpError(404, 'model_not_found', 'Unknown model.');
  if (!allowed(grant, model)) throw new HttpError(403, 'model_not_allowed', 'This site was not given access to that model.');
  const slash = model.indexOf('/');
  const base = Object.hasOwn(backends, model.slice(0, slash)) ? backends[model.slice(0, slash)] : null;
  if (!base) throw new HttpError(404, 'model_not_found', 'Unknown model.');

  const abort = new AbortController();
  res.on('close', () => abort.abort());
  let upstream;
  try {
    upstream = await fetch(`${base}/v1/chat/completions`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ...body, model: model.slice(slash + 1) }),
      signal: abort.signal,
    });
  } catch {
    if (abort.signal.aborted) return;
    throw new HttpError(502, 'backend_unavailable', 'The model server is not reachable.');
  }
  res.writeHead(upstream.status, {
    'Content-Type': upstream.headers.get('content-type') || 'application/json',
    'Cache-Control': 'no-store',
  });
  if (!upstream.body) return res.end();
  Readable.fromWeb(upstream.body).on('error', () => res.end()).pipe(res);
}

// ---------- Approval page (bridge's own origin; never CORS-enabled) ----------

const PAGE_HEADERS = {
  'Content-Type': 'text/html; charset=utf-8',
  'Cache-Control': 'no-store',
  'X-Frame-Options': 'DENY',
  // same-origin, not no-referrer: no-referrer makes browsers send "Origin: null" on the approval form.
  'Referrer-Policy': 'same-origin',
  'Content-Security-Policy': "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'",
};

function page(res, status, inner) {
  res.writeHead(status, PAGE_HEADERS);
  res.end(`<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>LocalLink</title><style>
:root{color-scheme:light dark;--bg:#f6f5f1;--card:#fff;--ink:#1c1b18;--mute:#6b6860;--line:#dedbd2;--go:#1f6f4a;--stop:#8a2c20}
@media(prefers-color-scheme:dark){:root{--bg:#161614;--card:#201f1c;--ink:#eeece6;--mute:#a09c92;--line:#3a3833;--go:#3fa675;--stop:#d0705f}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font:16px/1.5 system-ui,sans-serif;display:grid;place-items:center;min-height:100vh;padding:16px}
main{background:var(--card);border:1px solid var(--line);border-radius:14px;padding:28px;max-width:460px;width:100%}
h1{font-size:20px;margin:0 0 4px}p{margin:8px 0;color:var(--mute)}
.origin{font:600 17px ui-monospace,monospace;color:var(--ink);word-break:break-all;margin:14px 0 2px}
.code{font:600 28px ui-monospace,monospace;letter-spacing:2px;color:var(--ink);margin:4px 0 14px}
fieldset{border:1px solid var(--line);border-radius:10px;margin:16px 0;padding:10px 14px;max-height:220px;overflow:auto}
legend{color:var(--mute);font-size:13px;padding:0 6px}label{display:block;padding:3px 0;font:14px ui-monospace,monospace}
.row{display:flex;gap:10px;margin-top:18px}button{flex:1;font:600 15px system-ui;padding:11px;border-radius:9px;border:1px solid var(--line);background:none;color:var(--stop);cursor:pointer}
button.go{background:var(--go);border-color:var(--go);color:#fff}small{color:var(--mute)}
</style></head><body><main>${inner}</main></body></html>`);
}

function findBySecret(k) {
  sweep();
  for (const p of pending.values()) if (p.status === 'pending' && k && p.secret === k) return p;
  return null;
}

async function handleApprovePage(req, res, url) {
  const p = findBySecret(url.searchParams.get('k'));
  if (!p) return page(res, 404, '<h1>Request not found</h1><p>It expired or was already answered. Go back to the site and try again.</p>');
  const models = await listModels();
  const list = models.length
    ? models.map(m => `<label><input type="checkbox" name="model" value="${esc(m.id)}" checked> ${esc(m.id)}</label>`).join('')
    : '<small>No models found right now. Start Ollama or LM Studio; this site will see models as they appear.</small>';
  page(res, 200, `<h1>Let this site use your local models?</h1>
<div class="origin">${esc(p.origin)}</div>
${p.appName ? `<p>It calls itself “${esc(p.appName)}”.</p>` : ''}
<p>Check that the site shows this code:</p><div class="code">${esc(p.code)}</div>
<form method="post" action="/approve"><input type="hidden" name="k" value="${esc(p.secret)}">
<fieldset><legend>Models it may use</legend>${list}
${models.length ? '<label><input type="checkbox" name="future" value="1"> Also models I add later</label>' : '<input type="hidden" name="future" value="1">'}</fieldset>
<p><small>The site will be able to run these models on this computer. It cannot read your files or other sites’ chats.</small></p>
<div class="row"><button name="decision" value="deny">Deny</button><button class="go" name="decision" value="allow">Allow</button></div></form>`);
}

async function handleApprovePost(req, res) {
  if (!selfOrigins.includes(req.headers.origin)) return page(res, 403, '<h1>Blocked</h1><p>This request did not come from the approval page.</p>');
  const form = new URLSearchParams(await readBody(req));
  const p = findBySecret(form.get('k'));
  if (!p) return page(res, 404, '<h1>Request not found</h1><p>It expired or was already answered.</p>');

  if (form.get('decision') !== 'allow') {
    p.status = 'denied';
    cooldown.set(p.origin, Date.now() + DENY_COOLDOWN_MS);
    console.log(`Denied ${p.origin}`);
    return page(res, 200, `<h1>Denied</h1><p>${esc(p.origin)} was not given access. You can close this tab.</p>`);
  }
  const models = form.get('future') ? 'all' : form.getAll('model');
  const token = 'll_' + crypto.randomBytes(32).toString('base64url');
  const grants = loadGrants().filter(g => g.origin !== p.origin);
  grants.push({ hash: sha256(token), origin: p.origin, app_name: p.appName, models, created: new Date().toISOString() });
  saveGrants(grants);
  p.status = 'approved'; p.token = token;
  console.log(`Approved ${p.origin} (${models === 'all' ? 'all models' : models.length + ' models'})`);
  page(res, 200, `<h1>Connected</h1><p>${esc(p.origin)} can now use ${models === 'all' ? 'your local models' : 'the models you selected'}. You can close this tab and go back to the site.</p>
<p><small>To remove access later, run <code>locallink-bridge revoke ${esc(p.origin)}</code>.</small></p>`);
}

// ---------- Router ----------

let selfOrigin = '';
let selfOrigins = [];
let allowedHosts = [];

async function route(req, res) {
  if (!allowedHosts.includes(req.headers.host)) throw new HttpError(403, 'bad_host', 'Unexpected Host header.');
  const url = new URL(req.url, selfOrigin);
  const p = url.pathname;

  if (p === '/approve') {
    if (req.method === 'GET') return handleApprovePage(req, res, url);
    if (req.method === 'POST') return handleApprovePost(req, res);
    throw new HttpError(404, 'not_found', 'Not found.');
  }

  cors(req, res);
  if (req.method === 'OPTIONS') {
    res.writeHead(204, {
      'Access-Control-Allow-Methods': 'GET, POST, DELETE, OPTIONS',
      'Access-Control-Allow-Headers': 'Authorization, Content-Type',
      'Access-Control-Allow-Private-Network': 'true',
      'Access-Control-Max-Age': '600',
    });
    return res.end();
  }

  if (p === '/.well-known/locallink' && req.method === 'GET') {
    return json(res, 200, { protocol: 'locallink', version: '0.1', bridge: { name: 'locallink-bridge', version: VERSION } });
  }
  if (p === '/locallink/v1/pair' && req.method === 'POST') return handlePair(req, res);
  const poll = /^\/locallink\/v1\/pair\/(pr_[0-9a-f]+)$/.exec(p);
  if (poll && req.method === 'GET') return handlePairPoll(req, res, poll[1]);

  if (p === '/locallink/v1/session') {
    const grant = authenticate(req);
    if (req.method === 'GET') return json(res, 200, { origin: grant.origin, models: grant.models, created: grant.created });
    if (req.method === 'DELETE') {
      saveGrants(loadGrants().filter(g => g.hash !== grant.hash));
      res.writeHead(204); return res.end();
    }
  }
  if (p === '/locallink/v1/models' && req.method === 'GET') {
    const grant = authenticate(req);
    return json(res, 200, { object: 'list', data: (await listModels()).filter(m => allowed(grant, m.id)) });
  }
  if (p === '/locallink/v1/chat/completions' && req.method === 'POST') {
    return handleChat(req, res, authenticate(req));
  }
  throw new HttpError(404, 'not_found', 'Not found.');
}

const server = http.createServer((req, res) => {
  route(req, res).catch(err => {
    if (res.headersSent) return res.end();
    if (err instanceof HttpError) return json(res, err.status, { error: { code: err.code, message: err.message } });
    console.error(err);
    json(res, 500, { error: { code: 'internal', message: 'Bridge error.' } });
  });
});

function listen(ports) {
  const [port, ...rest] = ports;
  server.once('error', err => {
    if (err.code === 'EADDRINUSE' && rest.length) return listen(rest);
    fail(`Cannot listen on port ${port}: ${err.message}`);
  });
  server.listen(port, '127.0.0.1', () => {
    selfOrigin = `http://127.0.0.1:${port}`;
    selfOrigins = [selfOrigin, `http://localhost:${port}`];
    allowedHosts = [`127.0.0.1:${port}`, `localhost:${port}`];
    console.log(`LocalLink bridge ${VERSION} listening on ${selfOrigin}`);
    console.log('Backends: ' + Object.entries(backends).map(([n, u]) => `${n} (${u})`).join(', '));
    listModels().then(m => console.log(m.length ? `Models available: ${m.map(x => x.id).join(', ')}` : 'No models found yet. Start Ollama, LM Studio, or another OpenAI-compatible server.'));
  });
}
listen(opts.port ? [opts.port] : PORTS);
