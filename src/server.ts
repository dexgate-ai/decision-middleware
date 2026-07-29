#!/usr/bin/env node
/**
 * Minimal HTTP entry point for Dexgate decision middleware (contract v0.1).
 *
 * Endpoints:
 *   POST /v1/decide      → 200 DecisionResponse | 400 MALFORMED_REQUEST
 *   POST /v1/decide-safe → 200 DecisionResponse (always)
 *   GET  /health         → 200 { status, policy_version }
 *
 * No auth, no CORS, no storage, no Passport. Library API unchanged.
 *
 * CLI: `npx @dexgate/decision-middleware` or `npm start` / `npm run start:dist`
 */

import http from "node:http";
import { decide, decideSafe, DecisionRequestError, POLICY_VERSION } from "./index.js";

const DEFAULT_PORT = 8787;
const PORT = Number.parseInt(process.env.PORT ?? String(DEFAULT_PORT), 10);

const MAX_BODY_BYTES = 1_048_576; // 1 MiB

function logRequest(
  method: string,
  path: string,
  status: number,
  traceId: string | null
): void {
  const trace = traceId ? ` trace_id=${traceId}` : "";
  console.log(`${method} ${path} ${status}${trace}`);
}

function sendJson(
  res: http.ServerResponse,
  status: number,
  body: unknown,
  method: string,
  path: string,
  traceId: string | null = null
): void {
  const payload = JSON.stringify(body);
  res.writeHead(status, {
    "Content-Type": "application/json; charset=utf-8",
    "Content-Length": Buffer.byteLength(payload),
  });
  res.end(payload);
  logRequest(method, path, status, traceId);
}

function readBody(req: http.IncomingMessage): Promise<string> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    let total = 0;

    req.on("data", (chunk: Buffer) => {
      total += chunk.length;
      if (total > MAX_BODY_BYTES) {
        reject(new BodyTooLargeError());
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });

    req.on("end", () => {
      resolve(Buffer.concat(chunks).toString("utf8"));
    });

    req.on("error", reject);
  });
}

class BodyTooLargeError extends Error {
  constructor() {
    super(`Request body exceeds ${MAX_BODY_BYTES} bytes.`);
    this.name = "BodyTooLargeError";
  }
}

async function parseJsonBody(
  req: http.IncomingMessage
): Promise<{ ok: true; value: unknown } | { ok: false; error: string }> {
  let raw: string;
  try {
    raw = await readBody(req);
  } catch (err) {
    if (err instanceof BodyTooLargeError) {
      return { ok: false, error: err.message };
    }
    return { ok: false, error: "Failed to read request body." };
  }

  if (!raw.trim()) {
    return { ok: false, error: "Request body is empty." };
  }

  try {
    return { ok: true, value: JSON.parse(raw) as unknown };
  } catch {
    return { ok: false, error: "Request body is not valid JSON." };
  }
}

async function handleDecide(
  req: http.IncomingMessage,
  res: http.ServerResponse,
  path: string
): Promise<void> {
  const method = "POST";
  const parsed = await parseJsonBody(req);
  if (!parsed.ok) {
    sendJson(
      res,
      400,
      { error: parsed.error, code: "MALFORMED_REQUEST" },
      method,
      path
    );
    return;
  }

  try {
    const response = await decide(parsed.value);
    sendJson(res, 200, response, method, path, response.trace_id);
  } catch (err) {
    if (err instanceof DecisionRequestError) {
      sendJson(
        res,
        400,
        { error: err.message, code: "MALFORMED_REQUEST" },
        method,
        path
      );
      return;
    }
    sendJson(
      res,
      500,
      { error: "Internal server error.", code: "INTERNAL_ERROR" },
      method,
      path
    );
  }
}

async function handleDecideSafe(
  req: http.IncomingMessage,
  res: http.ServerResponse,
  path: string
): Promise<void> {
  const method = "POST";
  const parsed = await parseJsonBody(req);

  // decideSafe still needs *some* body to evaluate; empty/invalid JSON
  // becomes a deny-with-evidence response (always 200).
  const input = parsed.ok
    ? parsed.value
    : { _parse_error: parsed.error };

  const response = await decideSafe(input);
  sendJson(res, 200, response, method, path, response.trace_id);
}

function handleHealth(
  res: http.ServerResponse,
  method: string,
  path: string
): void {
  sendJson(
    res,
    200,
    { status: "ok", policy_version: POLICY_VERSION },
    method,
    path
  );
}

export function createServer(): http.Server {
  return http.createServer((req, res) => {
    const method = (req.method ?? "GET").toUpperCase();
    const url = new URL(req.url ?? "/", `http://${req.headers.host ?? "localhost"}`);
    const path = url.pathname;

    void (async () => {
      try {
        if (method === "GET" && path === "/health") {
          handleHealth(res, method, path);
          return;
        }

        if (method === "POST" && path === "/v1/decide") {
          await handleDecide(req, res, path);
          return;
        }

        if (method === "POST" && path === "/v1/decide-safe") {
          await handleDecideSafe(req, res, path);
          return;
        }

        sendJson(
          res,
          404,
          { error: "Not found.", code: "NOT_FOUND" },
          method,
          path
        );
      } catch {
        if (!res.headersSent) {
          sendJson(
            res,
            500,
            { error: "Internal server error.", code: "INTERNAL_ERROR" },
            method,
            path
          );
        }
      }
    })();
  });
}

export function startServer(port: number = PORT): http.Server {
  const server = createServer();
  server.listen(port, () => {
    console.log(
      `dexgate-decision-middleware listening on http://127.0.0.1:${port}`
    );
    console.log(`  GET  /health`);
    console.log(`  POST /v1/decide`);
    console.log(`  POST /v1/decide-safe`);
    console.log(`  policy_version=${POLICY_VERSION}`);
  });
  return server;
}

// Run when executed directly (tsx src/server.ts / node dist/server.js)
const isMain =
  process.argv[1] != null &&
  (process.argv[1].endsWith("server.ts") ||
    process.argv[1].endsWith("server.js"));

if (isMain) {
  startServer();
}
