# LocalLink Protocol — v0.1 (draft)

LocalLink lets a website use AI models running on the visitor's own computer.
The visitor picks "Local model" on the site, approves the site once, and the
site can then list the local models and run chat completions against them.
Prompts and responses travel only between the browser tab and the visitor's
machine.

## 1. Roles

| Role | What it is |
|---|---|
| **Site** | A web page that wants to use local models. Identified by its origin (`https://example.com`). |
| **Bridge** | A small program on the visitor's computer that speaks LocalLink on a loopback port. |
| **Backend** | A local model server (Ollama, LM Studio, llama.cpp, Jan, …) that exposes an OpenAI-compatible API. The bridge talks to backends; sites never do. |

Sites cannot talk to backends directly in a safe, uniform way: backends differ
in ports, most do not send CORS headers, and none ask the user which sites may
use them. The bridge supplies those three things: one well-known address,
correct browser headers, and per-site consent.

## 2. Transport

- HTTP/1.1 on `127.0.0.1`, default port **7465**. A bridge that cannot bind
  7465 uses 7466 or 7467. Sites probe these three ports in order.
- All bodies are JSON (`application/json`), except streamed completions, which
  are `text/event-stream`.
- The bridge MUST bind to loopback only.
- The bridge MUST reject any request whose `Host` header is not
  `127.0.0.1:<port>` or `localhost:<port>` (defence against DNS rebinding).

### 2.1 Browser headers

On every response to a site endpoint (sections 3–6) the bridge sends:

```
Access-Control-Allow-Origin: <the request's Origin>
Vary: Origin
```

On `OPTIONS` preflights it additionally sends:

```
Access-Control-Allow-Methods: GET, POST, DELETE, OPTIONS
Access-Control-Allow-Headers: Authorization, Content-Type
Access-Control-Allow-Private-Network: true
Access-Control-Max-Age: 600
```

The bridge never sends `Access-Control-Allow-Credentials`. Authentication is by
bearer token only, never by cookie.

## 3. Discovery

```
GET /.well-known/locallink
```

No authentication. Response:

```json
{
  "protocol": "locallink",
  "version": "0.1",
  "bridge": { "name": "locallink-bridge", "version": "0.1.0" }
}
```

The response MUST NOT reveal model names, backend names, hardware, or anything
else that differs between users beyond the bridge build. An unpaired site
learns only "a LocalLink bridge is present".

A site treats a network error on all three ports as "no bridge installed" and
SHOULD show the visitor how to install one.

## 4. Pairing

A site must be paired before it can see or use models. Pairing produces a
**grant**: a bearer token bound to the site's origin and to a set of models the
visitor chose.

### 4.1 Request

```
POST /locallink/v1/pair
{ "app_name": "Example Chat" }
```

`app_name` is optional, at most 64 characters, and is display text only. The
bridge identifies the site by the `Origin` header, never by `app_name`.

The bridge MUST refuse (`403 origin_not_allowed`) when `Origin` is missing,
is `null`, or is not a secure context origin (`https://…`, or `http://` on
`localhost` / `127.0.0.1`).

Response `201`:

```json
{
  "request_id": "pr_6f0c…",
  "code": "482-917",
  "expires_in": 120
}
```

`code` is a six-digit verification code. The site MUST display it so the
visitor can match it against the code on the approval screen.

### 4.2 Consent

On receiving a pair request the bridge shows an approval prompt outside the
site's control. The prompt MUST show the origin and the verification code, and
SHOULD let the visitor choose which models the site may use.

The reference bridge opens `http://127.0.0.1:<port>/approve?k=<secret>` in the
default browser. Requirements on such a prompt:

- `<secret>` is never sent to the site. `request_id` cannot be used to approve.
- The approval `POST` is accepted only when its `Origin` is the bridge's own.
- The page forbids framing (`X-Frame-Options: DENY`).
- Approval endpoints send no CORS headers.

### 4.3 Limits

- A pair request expires after 120 seconds.
- At most one pending request per origin (`429 pair_pending`).
- After a denial, the same origin is refused for 30 seconds (`429 pair_cooldown`).
- At most 5 pending requests in total (`429 too_many_requests`).

### 4.4 Poll

```
GET /locallink/v1/pair/<request_id>
```

Only the origin that created the request may poll it. Responses:

```json
{ "status": "pending" }
{ "status": "approved", "token": "ll_…" }
{ "status": "denied" }
{ "status": "expired" }
```

`approved` is returned exactly once; the bridge then forgets the request. The
site stores the token (for example in `localStorage`). Sites SHOULD poll about
once a second.

## 5. Using a grant

Every request in this section carries:

```
Authorization: Bearer ll_…
```

The bridge MUST check both that the token is valid and that the request's
`Origin` equals the origin the grant was issued to. A failure is `401
invalid_token`; the site SHOULD discard the token and offer to pair again.

### 5.1 Session

```
GET /locallink/v1/session       → { "origin": "...", "models": "all" | ["id", …], "created": "<ISO 8601>" }
DELETE /locallink/v1/session    → 204, grant revoked
```

### 5.2 List models

```
GET /locallink/v1/models
```

```json
{
  "object": "list",
  "data": [
    { "id": "ollama/llama3.2:3b", "object": "model", "backend": "ollama", "name": "llama3.2:3b" }
  ]
}
```

Model ids are `<backend>/<backend's own id>`. Only models covered by the grant
are listed. A backend that is not running contributes nothing; an empty list is
a valid response.

### 5.3 Chat completion

```
POST /locallink/v1/chat/completions
```

The request and response bodies follow the OpenAI Chat Completions format,
including `"stream": true` with server-sent events terminated by
`data: [DONE]`. `model` is a LocalLink model id from 5.2. The bridge forwards
the body to the backend unchanged apart from rewriting `model`.

Requesting a model outside the grant is `403 model_not_allowed`. An unknown
model or backend is `404 model_not_found`. A backend that cannot be reached is
`502 backend_unavailable`.

## 6. Errors

Every non-2xx response has this body:

```json
{ "error": { "code": "invalid_token", "message": "Human-readable explanation." } }
```

| Status | `code` |
|---|---|
| 400 | `bad_request` |
| 401 | `invalid_token` |
| 403 | `origin_not_allowed`, `model_not_allowed`, `bad_host` |
| 404 | `not_found`, `model_not_found` |
| 413 | `too_large` |
| 429 | `pair_pending`, `pair_cooldown`, `too_many_requests` |
| 502 | `backend_unavailable` |

## 7. Security model

**What a site can do without consent:** learn that a bridge is installed, and
cause one approval prompt per 30 seconds.

**What a paired site can do:** list and run the models in its grant, which
costs the visitor compute and power. It cannot read files, see other sites'
conversations, reach models outside its grant, or pull/delete models.

**Threats and mitigations**

| Threat | Mitigation |
|---|---|
| Any page silently using the visitor's GPU | Per-origin grant, explicit approval (4.2) |
| Site approves itself | Approval secret never leaves the bridge; approval POST is same-origin only; no framing |
| Token stolen from site A used by site B | Token is bound to origin; `Origin` is set by the browser and cannot be forged by page script |
| DNS rebinding to reach the bridge as a "same-origin" host | `Host` header allow-list (2) |
| Prompt spam | Pair limits (4.3) |
| Fingerprinting by model list | Discovery reveals nothing user-specific (3); models visible only after pairing |
| Non-browser local software forging `Origin` | Out of scope: software already running on the machine can reach the backends directly |

Bridges store only a hash of each token. Visitors can list and revoke grants
at the bridge at any time.

## 8. Browser notes

- Browsers treat `http://127.0.0.1` as a trustworthy origin, so HTTPS sites may
  fetch it without mixed-content blocking. Sites MUST use `127.0.0.1`, not
  `localhost`, in the fetch URL.
- Chromium shows its own "access devices on your local network" permission
  prompt the first time a public site contacts loopback. This is in addition
  to LocalLink pairing. The `Access-Control-Allow-Private-Network` header (2.1)
  covers the older preflight form of the same feature.
- Browsers that block loopback requests from public sites entirely cannot use
  LocalLink; a site sees this as "no bridge installed".

## 9. Not in v0.1

Embeddings, image input beyond what the backend accepts through the chat
format, tool-calling guarantees, per-site rate or token limits, model
download/management, and non-loopback (LAN) bridges.
