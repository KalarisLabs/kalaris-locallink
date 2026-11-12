# kalaris-locallink

[![test](https://github.com/KalarisLabs/kalaris-locallink/actions/workflows/test.yml/badge.svg)](https://github.com/KalarisLabs/kalaris-locallink/actions/workflows/test.yml)

Home of **LocalLink**, a protocol that lets websites use AI models running on the visitor's own computer.
The visitor picks "Local model" on a site, approves the site once, and the site can
list and chat with their local models (Ollama, LM Studio, llama.cpp, Jan, or any
OpenAI-compatible server).

| Path | What it is |
|---|---|
| `SPEC.md` | The protocol, v0.1 |
| `bridge/locallink-bridge.mjs` | The program the visitor runs. Zero dependencies, Node 18+ |
| `sdk/locallink.js` | What a website imports |
| `demo/` | A sample chat site |
| `test/` | End-to-end test and a mock model server |

## Try it

Three terminals:

```bash
node bridge/locallink-bridge.mjs
```

```bash
node demo/serve.mjs
```

Then open http://localhost:8787, choose **Local model on this computer**, and click
**Allow** in the approval tab that opens.

No model server installed? Run the mock one and point the bridge at it:

```bash
node test/mock-backend.mjs
```

```bash
node bridge/locallink-bridge.mjs --backend mock=http://127.0.0.1:9911
```

## Use it on a website

```js
import { LocalLink } from './locallink.js';

const link = await LocalLink.connect({
  appName: 'My App',
  onCode: code => showCode(code),          // user matches this against the approval screen
});
const models = await link.models();        // [{ id: 'ollama/llama3.2:3b', backend, name }]
for await (const text of link.chat({ model: models[0].id, messages })) append(text);
```

`LocalLink.resume()` reconnects a returning visitor without a prompt.

## Manage access

```bash
node bridge/locallink-bridge.mjs grants
```

```bash
node bridge/locallink-bridge.mjs revoke https://example.com
```

## Test

```bash
npm test
```

## Status

Draft v0.1. Tested against a mock OpenAI-compatible server; not yet verified against real Ollama or LM Studio installs or from public HTTPS sites.

## License

MIT
