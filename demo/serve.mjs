// Serves the demo site on http://localhost:8787 — a different origin from the bridge, like a real website.
import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const FILES = { '/': 'demo/index.html', '/locallink.js': 'sdk/locallink.js' };
const port = Number(process.argv[2]) || 8787;

http.createServer((req, res) => {
  const file = FILES[new URL(req.url, 'http://x').pathname];
  if (!file) { res.writeHead(404); return res.end('Not found'); }
  res.writeHead(200, { 'Content-Type': file.endsWith('.js') ? 'text/javascript' : 'text/html; charset=utf-8', 'Cache-Control': 'no-store' });
  fs.createReadStream(path.join(root, file)).pipe(res);
}).listen(port, 'localhost', () => console.log(`Demo site on http://localhost:${port}`));
