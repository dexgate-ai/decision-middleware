# @dexgate/decision-middleware

**Dexgate Decision Execution Governance** — core decision middleware (contract **v0.1**).

Language: **TypeScript** (Node.js ≥ 18).  
License: **MIT** (this package). The SDE PDP runtime is separate and proprietary.

This package sits between agent PEPs (e.g. OpenClaw Trusted Mode) and the **SDE Policy Decision Point**:

```text
OpenClaw (MIDDLEWARE mode)  →  this package (:8787 /v1/decide)  →  SDE PDP (:8001 /v1/authorize)
```

- `decide` / `decideSafe` → `DecisionResponse` (async)
- Policy evaluation via **SDE Enterprise PDP**
- `trace_id` per request; reconstructible **evidence**
- `passport` is **always `null`** in the decision-middleware v0.1 response; upstream SDE Passport issuance is not surfaced through this package
- Default when unclear or PDP failure = **deny** (fail closed)

This package does not issue Passports and does not persist decisions. Entitled SDE runtime workflows may still issue, verify, expire, and revoke Passports outside this envelope. The only network call from this package is to the configured SDE PDP.

## Install

```bash
# From npm (after public publish — not executed in prep releases):
npm install @dexgate/decision-middleware

# From this repo (development):
cd c:\dev\dexgate-decision-middleware
npm install
npm test
npm run build
```

Unit tests inject a mock PDP via `setAuthorizeFn` (no live PDP required).

### Point OpenClaw at this middleware

1. Run SDE PDP, then this service (see [HTTP server](#http-server)).
2. In `@dexgate/openclaw-trusted-mode` set **opt-in** governed mode (default remains free allowlist):

```json
{
  "toolPolicyMode": "MIDDLEWARE",
  "decisionMiddlewareUrl": "http://127.0.0.1:8787/v1/decide",
  "environment": "dev",
  "failClosed": true
}
```

Adapter docs: [openclaw-trusted-mode free vs governed](https://github.com/dexgate-ai/openclaw-trusted-mode) (local: `c:\dev\openclaw-trusted-mode\README.md`).

## HTTP server

Minimal Node `http` server (no Express/Fastify). Default port **8787** (`PORT` env overrides).

```bash
# Dev (tsx)
$env:SDE_PDP_URL = "http://127.0.0.1:8001/v1/authorize"
$env:SDE_PDP_TENANT_ID = "trial-tenant"
npm start

# Production-style (compiled)
npm run build
npm run start:dist
# or: npx @dexgate/decision-middleware
```

| Method | Path | Behavior |
|--------|------|----------|
| `GET` | `/health` | `{ "status": "ok", "policy_version": "..." }` |
| `POST` | `/v1/decide` | 200 `DecisionResponse` or 400 `MALFORMED_REQUEST` |
| `POST` | `/v1/decide-safe` | always 200 `DecisionResponse` |

Stdout logs:

- HTTP: `METHOD path status [trace_id=...]`
- Live PDP: `sde_pdp authorize sku=... decision=... latency_ms=... host=...` (no full payloads)
- **Decision summary (one JSON line per tool decision):**  
  `{"type":"decision_summary","tool":"…","decision":"allow|deny|…","deny_code":null,"latency_ms":12,"trace_id":"…","policy_variant":"…"}`  
  No tool arguments, tokens, or full evidence — light signal for conversion and policy tuning.

## Usage

```ts
import { decide, decideSafe } from "@dexgate/decision-middleware";

const response = await decide({
  tool_calls: [
    {
      id: "call-1",
      type: "function",
      function: {
        name: "read_file",
        arguments: JSON.stringify({ path: "README.md" }),
      },
    },
  ],
  context: {
    agent_id: "agent-1",
    session_id: "sess-1",
    model: "grok",
    trusted_mode: false,
    environment: "dev",
    deployment_id: null,
  },
});

// response.trace_id
// response.decisions[0].decision  // "allow" | "deny" | "constrain" | "escalate"
// response.decisions[0].passport  // null
// response.decisions[0].evidence  // always present
```

Use `decideSafe` when you want malformed top-level requests converted into a deny decision with evidence instead of throwing.

## Policy: SDE Enterprise PDP

Decisions are made by the SDE PDP at `C:\dev\sde-enterprise` (`ops/pdp_server.py`).

| Item | Value |
|------|--------|
| Endpoint | `POST /v1/authorize` |
| Default URL | `http://127.0.0.1:8001/v1/authorize` |
| Default timeout (total budget) | **4000 ms** (`SDE_PDP_TIMEOUT_MS`) |
| Retry | At most **1** retry on network error or HTTP **5xx** only |
| Default SKU | `openclaw.trusted_mode.authorize.v1` |
| Default tenant | `trial-tenant` |
| Default variant | `guard-pro.v2026.02` |

### SKU and policy_variant selection

Supported SKUs (exact SDE PDP strings):

| SKU | Input shape |
|-----|-------------|
| `openclaw.trusted_mode.authorize.v1` (**default**) | `inputs.action_request` |
| `codex.trusted_mode.authorize.v1` | `inputs.request` |

**Precedence** (highest → lowest) for both `decision_sku` and `policy_variant`:

1. **Request context** — optional fields on `DecisionRequest.context`
2. **Environment variables**
3. **Package defaults** (OpenClaw SKU + `guard-pro.v2026.02`)

Optional context fields (backward compatible when omitted):

```ts
context: {
  // …required fields…
  decision_sku?: string;   // e.g. "codex.trusted_mode.authorize.v1"
  sku?: string;            // alias for decision_sku (decision_sku wins if both set)
  policy_variant?: string; // e.g. "guard-pro.v2026.02" or "codex-guard.v0.1.0"
  tenant_id?: string;      // per-request SDE tenant (overrides SDE_PDP_TENANT_ID)
  gateway_id?: string;     // per-request SDE gateway (overrides SDE_PDP_GATEWAY_ID)
  environment: "dev" | "staging" | "production"; // see aliases below
}
```

### Environment vocabulary

Canonical values accepted after normalization:

| Canonical | Accepted aliases (case-insensitive) |
|-----------|-------------------------------------|
| `dev` | `development`, `local` |
| `staging` | `stage`, `stg`, `qa` |
| `production` | `prod`, `prd` |

Unknown labels are rejected at validation. PEPs should send canonical values when possible; aliases are normalized before authorize.

**Tenant / gateway routing:** Prefer per-request `context.tenant_id` and `context.gateway_id` when PEPs (e.g. OpenClaw) supply them. If omitted, the middleware falls back to process env defaults (`SDE_PDP_TENANT_ID`, `SDE_PDP_GATEWAY_ID`).

Example — Codex SKU for one request:

```json
{
  "tool_calls": [{ "id": "1", "type": "function", "function": { "name": "shell_command", "arguments": "{\"command\":\"Get-Content README.md\"}" } }],
  "context": {
    "agent_id": "agent-1",
    "session_id": "sess-1",
    "model": "codex",
    "trusted_mode": false,
    "environment": "dev",
    "deployment_id": null,
    "decision_sku": "codex.trusted_mode.authorize.v1",
    "policy_variant": "codex-guard.v0.1.0"
  }
}
```

### Timeout and retry policy

| Setting | Value |
|---------|--------|
| Default total budget | **4000 ms** (`SDE_PDP_TIMEOUT_MS`, clamped 500–60000) |
| Max attempts | **2** (1 initial + at most 1 retry) |
| Retries on | Network / transport failure, HTTP **5xx** |
| No retry on | HTTP **4xx**, auth failure, timeout, unparseable body, successful **2xx** (including `decision=deny`) |
| Budget | Wall-clock from first attempt; each attempt is capped by **remaining** budget |

Stdout (live only): `sde_pdp authorize sku=… decision=… latency_ms=… attempts=… host=…`  
Retry line: `sde_pdp authorize retry sku=… after=PDP_HTTP_ERROR attempt=1 remaining_ms=…`

### Fail-closed behavior

All PDP failures map to **deny** with reconstructible evidence. Primary risk_signal codes:

| Failure | Result | Evidence `risk_signal` code |
|---------|--------|------------------------------|
| Timeout / budget exhausted | **deny** | `sde_pdp_timeout` |
| Network / unreachable / bad URL | **deny** | `sde_pdp_transport_error` |
| HTTP error (incl. 4xx auth) | **deny** | `sde_pdp_http_error` |
| Unparseable body / unclear decision | **deny** | `sde_pdp_unclear_decision` |

### Env vars

| Variable | Required | Description |
|----------|----------|-------------|
| `SDE_PDP_URL` / `PDP_URL` | Recommended | Full authorize URL. Defaults to local PDP if unset. |
| `SDE_PDP_AUTH_TOKEN` / `PDP_AUTH_TOKEN` | Optional | Bearer token when PDP requires runtime auth |
| `SDE_PDP_TENANT_ID` / `TENANT_ID` | Optional | Default `trial-tenant` |
| `SDE_PDP_POLICY_VARIANT` / `POLICY_VARIANT` | Optional | Default `guard-pro.v2026.02` |
| `SDE_PDP_SKU` / `SDE_PDP_DECISION_SKU` | Optional | Default OpenClaw SKU (`SDE_PDP_SKU` preferred) |
| `SDE_PDP_TIMEOUT_MS` | Optional | Total budget ms; default `4000` |
| `SDE_PDP_GATEWAY_ID` | Optional | Gateway id forwarded to PDP |

Mapping:

- OpenClaw SKU: tool call → `inputs.action_request.{ tool_name, params, origin, … }`
- Codex SKU: tool call → `inputs.request.{ runtime, toolName, command, origin, … }`
- `context.environment` → top-level `environment`
- PDP `decision` → Dexgate `allow|deny|constrain|escalate`
- Upstream SDE Passport material is **not** returned (`passport` is always `null` in this package’s v0.1 response)

`decide` / `decideSafe` / `evaluatePolicy` are **async** (HTTP I/O).

## Live full stack (OpenClaw → middleware → PDP)

For end-to-end checks with the OpenClaw trusted-mode plugin in `MIDDLEWARE` mode, use the script and runbook in the adapter repo:

- `c:\dev\openclaw-trusted-mode\scripts\verify_live_governed_path.js`
- `c:\dev\openclaw-trusted-mode\docs\LIVE_GOVERNED_PATH_VERIFICATION.md`

Startup order: **SDE PDP (:8001) → this middleware (:8787) → verification script / OpenClaw**.

```powershell
# this package
$env:SDE_PDP_URL = "http://127.0.0.1:8001/v1/authorize"
$env:SDE_PDP_TENANT_ID = "trial-tenant"
$env:PORT = "8787"
npm start
```

## Live PDP Verification

Use this when you have a running SDE PDP (for example from `C:\dev\sde-enterprise`).

### 1. Required / recommended env

```powershell
# Required for a known live target (defaults to localhost:8001 if omitted)
$env:SDE_PDP_URL = "http://127.0.0.1:8001/v1/authorize"

# Optional but common
$env:SDE_PDP_TENANT_ID = "trial-tenant"
$env:SDE_PDP_POLICY_VARIANT = "guard-pro.v2026.02"
# $env:SDE_PDP_AUTH_TOKEN = "<runtime bearer if PDP_AUTH_TOKEN is set on the PDP>"
$env:SDE_PDP_TIMEOUT_MS = "4000"

# Middleware listen port (optional)
$env:PORT = "8787"
```

Confirm the PDP itself is up:

```powershell
curl.exe -s http://127.0.0.1:8001/healthz
# expect: {"status":"ok"}
```

### 2. Start the middleware against that PDP

```powershell
cd c:\dev\dexgate-decision-middleware
npm start
```

Watch stdout for lines like:

```text
dexgate-decision-middleware listening on http://127.0.0.1:8787
sde_pdp authorize sku=openclaw.trusted_mode.authorize.v1 decision=allow latency_ms=42 host=127.0.0.1:8001
POST /v1/decide 200 trace_id=...
```

### 3. Example curls

**Allow** — low-risk `read_file` in `dev` (typical Guard Pro allow):

```powershell
curl.exe -s -X POST http://127.0.0.1:8787/v1/decide `
  -H "Content-Type: application/json" `
  -d "{\"tool_calls\":[{\"id\":\"tc-allow\",\"type\":\"function\",\"function\":{\"name\":\"read_file\",\"arguments\":\"{\\\"path\\\":\\\"README.md\\\"}\"}}],\"context\":{\"agent_id\":\"agent-1\",\"session_id\":\"sess-1\",\"model\":\"grok\",\"trusted_mode\":false,\"environment\":\"dev\",\"deployment_id\":null}}"
```

Expect `decisions[0].decision` = `"allow"`, `passport` = `null`, and evidence risk signals including `sde_pdp_request`.

**Deny** — shell execution (Guard Pro blocks `execute_shell` / `shell`):

```powershell
curl.exe -s -X POST http://127.0.0.1:8787/v1/decide `
  -H "Content-Type: application/json" `
  -d "{\"tool_calls\":[{\"id\":\"tc-deny\",\"type\":\"function\",\"function\":{\"name\":\"shell\",\"arguments\":\"{\\\"command\\\":\\\"rm -rf /\\\"}\"}}],\"context\":{\"agent_id\":\"agent-1\",\"session_id\":\"sess-1\",\"model\":\"grok\",\"trusted_mode\":false,\"environment\":\"production\",\"deployment_id\":\"dep-1\"}}"
```

Expect `decisions[0].decision` = `"deny"`, reason mentioning SDE PDP, and often `sde_pdp_deny_code` in evidence.

**Fail-closed (PDP down)** — stop the PDP, then repeat either call. Expect `decision` = `"deny"` with `sde_pdp_timeout` or `sde_pdp_transport_error` in `evidence.risk_signals`.

### 4. What a successful evidence block looks like

```json
{
  "tool_call_id": "tc-allow",
  "decision": "allow",
  "reason": "Allowed by SDE PDP for tool \"read_file\".",
  "modified_arguments": null,
  "passport": null,
  "evidence": {
    "proposal": {
      "tool_call_id": "tc-allow",
      "tool_name": "read_file",
      "arguments_raw": "{\"path\":\"README.md\"}",
      "arguments_parsed": { "path": "README.md" },
      "parse_error": null
    },
    "policy_version": "0.1.0-starter",
    "evaluated_at": "2026-07-29T13:00:00.000Z",
    "risk_signals": [
      {
        "code": "sde_pdp_request",
        "severity": "info",
        "message": "decision_sku=openclaw.trusted_mode.authorize.v1; tenant_id=trial-tenant; environment=dev; tool=read_file"
      },
      {
        "code": "sde_pdp_policy_variant",
        "severity": "info",
        "message": "SDE PDP policy_variant=guard-pro.v2026.02"
      },
      {
        "code": "sde_pdp_decision_hash",
        "severity": "info",
        "message": "<hash-from-pdp>"
      }
    ]
  }
}
```

## Layout

```
src/
  types.ts            # Contract types (v0.1)
  policy.ts           # evaluatePolicy → SDE PDP
  sde-pdp-client.ts   # HTTP client, timeout, live logging, mock injection
  sde-pdp-adapter.ts  # Request/response mapping + fail-closed signals
  middleware.ts       # decide / decideSafe / validateRequest
  server.ts           # HTTP entry point (POST /v1/decide, …)
  index.ts            # Public library exports
tests/
  middleware.test.ts
  sde-pdp-adapter.test.ts
```

## Publish note

Package metadata is prepared for `@dexgate/decision-middleware` public publish (`publishConfig.access: public`).  
**Do not publish until** `c:\dev\openclaw-trusted-mode\RELEASE_CHECKLIST.md` sign-off.
