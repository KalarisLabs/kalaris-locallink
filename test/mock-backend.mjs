// A stand-in for Ollama / LM Studio: an OpenAI-compatible server with two fake models.
// node test/mock-backend.mjs [port]   (default 9911)
import http from 'node:http';

const port = Number(process.argv[2]) || 9911;
const MODELS = ['echo-small', 'echo-large'];

http.createServer(async (req, res) => {
  if (req.url === '/v1/models') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    return res.end(JSON.stringify({ object: 'list', data: MODELS.map(id => ({ id, object: 'model' })) }));
  }
  if (req.url === '/v1/chat/completions' && req.method === 'POST') {
    let raw = '';
    for await (const c of req) raw += c;
    const body = JSON.parse(raw);
    const last = body.messages?.at(-1)?.content ?? '';
    const reply = `[${body.model}] You said: ${last}`;
    if (!body.stream) {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      return res.end(JSON.stringify({ object: 'chat.completion', model: body.model, choices: [{ index: 0, message: { role: 'assistant', content: reply }, finish_reason: 'stop' }] }));
    }
    res.writeHead(200, { 'Content-Type': 'text/event-stream' });
    for (const word of reply.split(/(?<= )/)) {
      res.write(`data: ${JSON.stringify({ object: 'chat.completion.chunk', model: body.model, choices: [{ index: 0, delta: { content: word } }] })}\n\n`);
      await new Promise(r => setTimeout(r, 60));
    }
    res.write('data: [DONE]\n\n');
    return res.end();
  }
  res.writeHead(404); res.end();
}).listen(port, '127.0.0.1', () => console.log(`Mock model server on http://127.0.0.1:${port}`));
