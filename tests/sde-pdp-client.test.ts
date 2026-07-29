/**
 * Live HTTP client behavior: timeout budget, retry on network/5xx, no retry on 4xx.
 */

import assert from "node:assert/strict";
import { afterEach, describe, it } from "node:test";
import {
  DEFAULT_PDP_TIMEOUT_MS,
  MAX_PDP_ATTEMPTS,
  SdePdpError,
  clampTimeoutMs,
  httpAuthorize,
  isRetriablePdpError,
  mapPdpFailure,
  type SdeAuthorizeRequest,
  type SdePdpConfig,
} from "../src/index.ts";

const originalFetch = globalThis.fetch;

const baseBody: SdeAuthorizeRequest = {
  decision_sku: "openclaw.trusted_mode.authorize.v1",
  policy_variant: "guard-pro.v2026.02",
  tenant_id: "trial-tenant",
  environment: "dev",
  inputs: {
    action_request: { tool_name: "read_file", params: {} },
  },
};

function baseConfig(overrides: Partial<SdePdpConfig> = {}): SdePdpConfig {
  return {
    authorizeUrl: "http://127.0.0.1:8001/v1/authorize",
    tenantId: "trial-tenant",
    policyVariant: "guard-pro.v2026.02",
    decisionSku: "openclaw.trusted_mode.authorize.v1",
    timeoutMs: 2000,
    ...overrides,
  };
}

function jsonResponse(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

afterEach(() => {
  globalThis.fetch = originalFetch;
});

describe("defaults and helpers", () => {
  it("default timeout is 4000ms", () => {
    assert.equal(DEFAULT_PDP_TIMEOUT_MS, 4000);
    assert.equal(MAX_PDP_ATTEMPTS, 2);
    assert.equal(clampTimeoutMs(0), 4000);
    assert.equal(clampTimeoutMs(3000), 3000);
  });

  it("isRetriablePdpError only for transport and 5xx", () => {
    assert.equal(
      isRetriablePdpError(new SdePdpError("x", "PDP_TRANSPORT_ERROR")),
      true
    );
    assert.equal(
      isRetriablePdpError(
        new SdePdpError("x", "PDP_HTTP_ERROR", { status: 503 })
      ),
      true
    );
    assert.equal(
      isRetriablePdpError(
        new SdePdpError("x", "PDP_HTTP_ERROR", { status: 400 })
      ),
      false
    );
    assert.equal(
      isRetriablePdpError(new SdePdpError("x", "PDP_AUTH_FAILED", { status: 401 })),
      false
    );
    assert.equal(
      isRetriablePdpError(new SdePdpError("x", "PDP_TIMEOUT")),
      false
    );
    assert.equal(
      isRetriablePdpError(new SdePdpError("x", "PDP_INVALID_RESPONSE")),
      false
    );
  });
});

describe("httpAuthorize retry", () => {
  it("retries once on HTTP 503 then succeeds", async () => {
    let calls = 0;
    globalThis.fetch = async () => {
      calls += 1;
      if (calls === 1) {
        return jsonResponse(503, { detail: "busy" });
      }
      return jsonResponse(200, { decision: "allow", decision_hash: "ok" });
    };

    const res = await httpAuthorize(baseBody, baseConfig());
    assert.equal(calls, 2);
    assert.equal(res.decision, "allow");
  });

  it("retries once on network error then succeeds", async () => {
    let calls = 0;
    globalThis.fetch = async () => {
      calls += 1;
      if (calls === 1) {
        throw new TypeError("fetch failed");
      }
      return jsonResponse(200, { decision: "deny", deny_code: "X", deny_reason: "no" });
    };

    const res = await httpAuthorize(baseBody, baseConfig());
    assert.equal(calls, 2);
    // Clear deny is a successful 2xx — not retried further.
    assert.equal(res.decision, "deny");
  });

  it("does not retry on HTTP 400", async () => {
    let calls = 0;
    globalThis.fetch = async () => {
      calls += 1;
      return jsonResponse(400, { detail: "bad request" });
    };

    await assert.rejects(
      () => httpAuthorize(baseBody, baseConfig()),
      (err: unknown) => {
        assert.ok(err instanceof SdePdpError);
        assert.equal(err.code, "PDP_HTTP_ERROR");
        assert.equal(err.status, 400);
        assert.equal(err.attempts, 1);
        return true;
      }
    );
    assert.equal(calls, 1);
  });

  it("does not retry on HTTP 401", async () => {
    let calls = 0;
    globalThis.fetch = async () => {
      calls += 1;
      return jsonResponse(401, { detail: "unauthorized" });
    };

    await assert.rejects(
      () => httpAuthorize(baseBody, baseConfig()),
      (err: unknown) => {
        assert.ok(err instanceof SdePdpError);
        assert.equal(err.code, "PDP_AUTH_FAILED");
        assert.equal(err.attempts, 1);
        return true;
      }
    );
    assert.equal(calls, 1);
  });

  it("does not retry a successful decision=deny (2xx)", async () => {
    let calls = 0;
    globalThis.fetch = async () => {
      calls += 1;
      return jsonResponse(200, {
        decision: "deny",
        deny_code: "POLICY_DENY",
        deny_reason: "blocked",
      });
    };

    const res = await httpAuthorize(baseBody, baseConfig());
    assert.equal(calls, 1);
    assert.equal(res.decision, "deny");
  });

  it("fails after one retry when 5xx persists", async () => {
    let calls = 0;
    globalThis.fetch = async () => {
      calls += 1;
      return jsonResponse(502, { detail: "bad gateway" });
    };

    await assert.rejects(
      () => httpAuthorize(baseBody, baseConfig()),
      (err: unknown) => {
        assert.ok(err instanceof SdePdpError);
        assert.equal(err.code, "PDP_HTTP_ERROR");
        assert.equal(err.status, 502);
        assert.equal(err.attempts, 2);
        return true;
      }
    );
    assert.equal(calls, 2);
  });
});

describe("httpAuthorize timeout budget", () => {
  it("aborts when attempt exceeds budget and maps to PDP_TIMEOUT", async () => {
    globalThis.fetch = async (_url, init) => {
      const signal = init?.signal;
      return new Promise<Response>((_resolve, reject) => {
        if (signal?.aborted) {
          const e = new Error("The operation was aborted");
          e.name = "AbortError";
          reject(e);
          return;
        }
        signal?.addEventListener("abort", () => {
          const e = new Error("The operation was aborted");
          e.name = "AbortError";
          reject(e);
        });
        // never resolves — wait for abort
      });
    };

    // clampTimeoutMs enforces a 500ms floor.
    const started = Date.now();
    await assert.rejects(
      () => httpAuthorize(baseBody, baseConfig({ timeoutMs: 500 })),
      (err: unknown) => {
        assert.ok(err instanceof SdePdpError);
        assert.equal(err.code, "PDP_TIMEOUT");
        return true;
      }
    );
    const elapsed = Date.now() - started;
    // Should finish near budget (~500ms), not hang.
    assert.ok(elapsed >= 400, `elapsed ${elapsed}ms too fast`);
    assert.ok(elapsed < 2000, `elapsed ${elapsed}ms too long`);
  });
});

describe("mapPdpFailure risk signal codes", () => {
  const req: SdeAuthorizeRequest = {
    decision_sku: "openclaw.trusted_mode.authorize.v1",
    policy_variant: "guard-pro.v2026.02",
    inputs: {},
  };

  it("maps timeout / transport / http to distinct codes", () => {
    assert.equal(
      mapPdpFailure(new SdePdpError("t", "PDP_TIMEOUT"), req, "t").risk_signals[0]
        ?.code,
      "sde_pdp_timeout"
    );
    assert.equal(
      mapPdpFailure(new SdePdpError("n", "PDP_TRANSPORT_ERROR"), req, "t")
        .risk_signals[0]?.code,
      "sde_pdp_transport_error"
    );
    assert.equal(
      mapPdpFailure(
        new SdePdpError("h", "PDP_HTTP_ERROR", { status: 502 }),
        req,
        "t"
      ).risk_signals[0]?.code,
      "sde_pdp_http_error"
    );
    assert.equal(
      mapPdpFailure(new SdePdpError("b", "PDP_INVALID_RESPONSE"), req, "t")
        .risk_signals[0]?.code,
      "sde_pdp_unclear_decision"
    );
  });

  it("always deny (fail closed)", () => {
    const out = mapPdpFailure(
      new SdePdpError("down", "PDP_TRANSPORT_ERROR", { attempts: 2 }),
      req,
      "read_file"
    );
    assert.equal(out.decision, "deny");
    assert.ok(out.risk_signals.some((s) => s.code === "default_deny"));
    assert.match(out.risk_signals[0]!.message, /attempts=2/);
  });
});
