/**
 * SDE PDP adapter mapping tests.
 *
 * Proves:
 * - Key Dexgate context fields appear as structured OpenClaw PDP fields
 * - PDP decision shapes map to allow | deny | constrain | escalate
 * - Unclear / partial PDP responses fail closed
 */

import assert from "node:assert/strict";
import { afterEach, describe, it } from "node:test";
import {
  assertValidAuthorizeUrl,
  buildAuthorizeRequest,
  buildOpenClawActionRequest,
  buildOriginMetadata,
  decide,
  evaluatePolicy,
  mapAuthorizeResponse,
  mapPdpFailure,
  normalizePdpDecision,
  setAuthorizeFn,
  SdePdpError,
  type DecisionContext,
  type SdeAuthorizeRequest,
} from "../src/index.ts";

const openClawConfig = {
  authorizeUrl: "http://127.0.0.1:8001/v1/authorize",
  tenantId: "trial-tenant",
  policyVariant: "guard-pro.v2026.02",
  decisionSku: "openclaw.trusted_mode.authorize.v1",
  timeoutMs: 1000,
  gatewayId: "gw-1",
};

const ctx: DecisionContext = {
  agent_id: "agent-x",
  session_id: "sess-x",
  model: "grok",
  trusted_mode: true,
  environment: "production",
  deployment_id: "dep-7",
};

const baseReq: SdeAuthorizeRequest = {
  decision_sku: "openclaw.trusted_mode.authorize.v1",
  policy_variant: "guard-pro.v2026.02",
  inputs: { action_request: { tool_name: "read_file" } },
  tenant_id: "trial-tenant",
  environment: "dev",
};

afterEach(() => {
  setAuthorizeFn(null);
});

// ---------------------------------------------------------------------------
// URL validation (regression)
// ---------------------------------------------------------------------------
describe("assertValidAuthorizeUrl", () => {
  it("accepts a valid absolute http URL", () => {
    assert.equal(
      assertValidAuthorizeUrl("http://127.0.0.1:8001/v1/authorize"),
      "http://127.0.0.1:8001/v1/authorize"
    );
  });

  it("rejects missing / empty URL", () => {
    assert.throws(
      () => assertValidAuthorizeUrl(""),
      (err: unknown) => {
        assert.ok(err instanceof SdePdpError);
        assert.equal(err.code, "PDP_URL_MISSING");
        return true;
      }
    );
  });
});

// ---------------------------------------------------------------------------
// Outbound OpenClaw mapping — context fields in structured places
// ---------------------------------------------------------------------------
describe("buildAuthorizeRequest (openclaw SKU) context mapping", () => {
  it("places tool_name, params, and all context fields on action_request + origin", () => {
    const body = buildAuthorizeRequest(
      "apply_patch",
      { path: "a.ts", patch: "diff" },
      ctx,
      openClawConfig
    );

    assert.equal(body.decision_sku, "openclaw.trusted_mode.authorize.v1");
    assert.equal(body.tenant_id, "trial-tenant");
    assert.equal(body.environment, "production");
    assert.equal(body.gateway_id, "gw-1");
    assert.equal(body.policy_variant, "guard-pro.v2026.02");

    // Top-level inputs carry environment / gateway for PDP helpers.
    assert.equal(body.inputs.environment, "production");
    assert.equal(body.inputs.gateway_id, "gw-1");

    const action = body.inputs.action_request as Record<string, unknown>;
    assert.ok(action, "action_request must be present");
    assert.equal(action.tool_name, "apply_patch");
    assert.equal(action.toolName, "apply_patch");
    assert.deepEqual(action.params, { path: "a.ts", patch: "diff" });

    // Structured context fields (not only stuffed into a blob).
    assert.equal(action.environment, "production");
    assert.equal(action.trusted_mode, true);
    assert.equal(action.agent_id, "agent-x");
    assert.equal(action.session_id, "sess-x");
    assert.equal(action.model, "grok");
    assert.equal(action.deployment_id, "dep-7");

    // Passport-friendly path aliases derived from params.
    assert.equal(action.path, "a.ts");
    assert.equal(action.targetPath, "a.ts");
    assert.equal(action.target_path, "a.ts");

    const origin = action.origin as Record<string, unknown>;
    assert.equal(origin.agent, "agent-x");
    assert.equal(origin.agent_id, "agent-x");
    assert.equal(origin.session_id, "sess-x");
    assert.equal(origin.model, "grok");
    assert.equal(origin.environment, "production");
    assert.equal(origin.trusted_mode, true);
    assert.equal(origin.deployment_id, "dep-7");
    assert.equal(origin.deployment_environment, "production");
    assert.equal(origin.adapter, "dexgate-decision-middleware");
    assert.equal(typeof origin.adapter_version, "string");
  });

  it("surfaces shell command as top-level action_request.command", () => {
    const action = buildOpenClawActionRequest(
      "shell",
      { command: "git push origin main" },
      { ...ctx, trusted_mode: false, environment: "dev", deployment_id: null }
    );
    assert.equal(action.tool_name, "shell");
    assert.equal(action.command, "git push origin main");
    assert.equal(action.deployment_id, null);
    assert.deepEqual(action.params, { command: "git push origin main" });
  });

  it("buildOriginMetadata includes only known origin-contract fields", () => {
    const origin = buildOriginMetadata({
      agent_id: "a1",
      session_id: "s1",
      model: "m1",
      trusted_mode: false,
      environment: "staging",
      deployment_id: null,
    });
    assert.equal(origin.agent, "a1");
    assert.equal(origin.session_id, "s1");
    assert.equal(origin.environment, "staging");
    assert.equal(origin.trusted_mode, false);
    assert.equal("deployment_id" in origin, false);
  });

  it("trims tool name and handles empty args as empty params object", () => {
    const action = buildOpenClawActionRequest("  read_file  ", null, ctx);
    assert.equal(action.tool_name, "read_file");
    assert.deepEqual(action.params, {});
  });

  it("forwards per-request tenant_id and gateway_id over env defaults", () => {
    const body = buildAuthorizeRequest(
      "read_file",
      { path: "x.md" },
      {
        ...ctx,
        tenant_id: "customer-tenant-42",
        gateway_id: "gw-customer-9",
      },
      openClawConfig // env defaults trial-tenant / gw-1
    );

    assert.equal(body.tenant_id, "customer-tenant-42");
    assert.equal(body.gateway_id, "gw-customer-9");
    assert.equal(body.inputs.gateway_id, "gw-customer-9");

    const action = body.inputs.action_request as Record<string, unknown>;
    const origin = action.origin as Record<string, unknown>;
    assert.equal(origin.tenant_id, "customer-tenant-42");
    assert.equal(origin.gateway_id, "gw-customer-9");
  });

  it("falls back to env tenant/gateway when context omits them", () => {
    const body = buildAuthorizeRequest(
      "read_file",
      {},
      { ...ctx, tenant_id: undefined, gateway_id: undefined },
      openClawConfig
    );
    assert.equal(body.tenant_id, "trial-tenant");
    assert.equal(body.gateway_id, "gw-1");
  });
});

// ---------------------------------------------------------------------------
// Inbound PDP → Dexgate outcomes
// ---------------------------------------------------------------------------
describe("normalizePdpDecision", () => {
  it("normalizes case and synonyms", () => {
    assert.equal(normalizePdpDecision("ALLOW"), "allow");
    assert.equal(normalizePdpDecision("Denied"), "deny");
    assert.equal(normalizePdpDecision("constrain"), "constrain");
    assert.equal(normalizePdpDecision("requires_approval"), "escalate");
    assert.equal(normalizePdpDecision("maybe"), null);
    assert.equal(normalizePdpDecision(null), null);
    assert.equal(normalizePdpDecision(42), null);
  });
});

describe("mapAuthorizeResponse decision shapes", () => {
  it("maps allow with reconstructible evidence signals", () => {
    const out = mapAuthorizeResponse(
      {
        decision: "allow",
        decision_hash: "h1",
        trace: {
          policy_variant: "guard-pro.v2026.02",
          policy_pack_version: "guard-pro.v2026.02",
          blast_radius_score: 5,
          action_class: "other",
          risk_classification_label: "Low",
        },
      },
      baseReq,
      "read_file"
    );
    assert.equal(out.decision, "allow");
    assert.match(out.reason, /Allowed by SDE PDP/);
    assert.equal(out.modified_arguments, null);
    assert.ok(out.risk_signals.some((s) => s.code === "sde_pdp_decision_hash"));
    assert.ok(out.risk_signals.some((s) => s.code === "sde_pdp_mapped_decision"));
    assert.ok(out.risk_signals.some((s) => s.code === "sde_pdp_action_class"));
    assert.ok(out.pdp_raw);
    assert.equal(out.pdp_request.decision_sku, baseReq.decision_sku);
  });

  it("maps deny with deny_code and deny_reason in reason + signals", () => {
    const out = mapAuthorizeResponse(
      {
        decision: "deny",
        deny_code: "HIGH_BLAST",
        deny_reason: "Shell execution blocked by default policy",
        decision_hash: "deny-hash",
        trace: { policy_variant: "guard-pro.v2026.02", blast_radius_score: 90 },
      },
      baseReq,
      "shell"
    );
    assert.equal(out.decision, "deny");
    assert.match(out.reason, /\[HIGH_BLAST\]/);
    assert.match(out.reason, /Shell execution blocked/);
    assert.ok(out.risk_signals.some((s) => s.code === "sde_pdp_deny_code" && s.message === "HIGH_BLAST"));
    assert.ok(
      out.risk_signals.some(
        (s) =>
          s.code === "sde_pdp_deny_reason" &&
          s.message.includes("Shell execution blocked")
      )
    );
    assert.equal(out.modified_arguments, null);
  });

  it("maps allow+constraints to constrain and surfaces constraints", () => {
    const constraints = [{ key: "path", allowed_prefixes: ["/tmp", "/safe"] }];
    const out = mapAuthorizeResponse(
      {
        decision: "allow",
        constraints,
        decision_hash: "c1",
      },
      baseReq,
      "write_file"
    );
    assert.equal(out.decision, "constrain");
    assert.match(out.reason, /constraint/i);
    assert.match(out.reason, /allowed_prefixes|\/tmp/);
    assert.equal(out.modified_arguments, null);
    assert.ok(out.risk_signals.some((s) => s.code === "sde_pdp_constraints"));
    assert.ok(
      out.risk_signals.some((s) => s.code === "sde_pdp_allow_with_constraints")
    );
  });

  it("maps native constrain decision", () => {
    const out = mapAuthorizeResponse(
      {
        decision: "constrain",
        constraints: [{ mode: "read_only" }],
      },
      baseReq,
      "write_file"
    );
    assert.equal(out.decision, "constrain");
    assert.ok(out.risk_signals.some((s) => s.code === "sde_pdp_constraints"));
  });

  it("maps escalate decision", () => {
    const out = mapAuthorizeResponse(
      {
        decision: "escalate",
        deny_code: "APPROVAL_REQUIRED",
        deny_reason: "Needs two-person approval",
      },
      baseReq,
      "deploy_service"
    );
    assert.equal(out.decision, "escalate");
    assert.match(out.reason, /Escalated|APPROVAL_REQUIRED|two-person/i);
  });

  it("maps uppercase ALLOW", () => {
    const out = mapAuthorizeResponse(
      { decision: "ALLOW" },
      baseReq,
      "read_file"
    );
    assert.equal(out.decision, "allow");
  });
});

// ---------------------------------------------------------------------------
// Fail closed — unclear / partial
// ---------------------------------------------------------------------------
describe("mapAuthorizeResponse fail-closed partial/unclear", () => {
  it("defaults unknown decision string to deny", () => {
    const out = mapAuthorizeResponse(
      { decision: "maybe" },
      baseReq,
      "weird"
    );
    assert.equal(out.decision, "deny");
    assert.ok(
      out.risk_signals.some((s) => s.code === "sde_pdp_unclear_decision")
    );
    assert.ok(out.risk_signals.some((s) => s.code === "default_deny"));
  });

  it("treats missing decision + deny_code as deny (partial)", () => {
    const out = mapAuthorizeResponse(
      {
        deny_code: "ENTITLEMENT_DENIED",
        deny_reason: "Tenant not entitled",
      },
      baseReq,
      "read_file"
    );
    assert.equal(out.decision, "deny");
    assert.match(out.reason, /ENTITLEMENT_DENIED|not entitled/i);
    assert.ok(
      out.risk_signals.some((s) => s.code === "sde_pdp_partial_response")
    );
  });

  it("treats empty object as unclear deny", () => {
    const out = mapAuthorizeResponse({}, baseReq, "read_file");
    assert.equal(out.decision, "deny");
    assert.ok(
      out.risk_signals.some((s) => s.code === "sde_pdp_unclear_decision")
    );
  });

  it("treats null response as unusable deny", () => {
    const out = mapAuthorizeResponse(
      null as unknown as SdeAuthorizeRequest as never,
      baseReq,
      "read_file"
    );
    assert.equal(out.decision, "deny");
    assert.equal(out.pdp_raw, null);
  });

  it("treats non-string decision as unclear deny", () => {
    const out = mapAuthorizeResponse(
      { decision: { nested: true } as unknown as string },
      baseReq,
      "read_file"
    );
    assert.equal(out.decision, "deny");
  });
});

// ---------------------------------------------------------------------------
// Transport fail-closed
// ---------------------------------------------------------------------------
describe("mapPdpFailure / evaluatePolicy fail-closed", () => {
  it("mapPdpFailure maps transport error to sde_pdp_transport_error", () => {
    const out = mapPdpFailure(
      new SdePdpError("down", "PDP_TRANSPORT_ERROR", { latencyMs: 12 }),
      baseReq,
      "read_file"
    );
    assert.equal(out.decision, "deny");
    assert.ok(
      out.risk_signals.some((s) => s.code === "sde_pdp_transport_error")
    );
  });

  it("mapPdpFailure maps timeout to sde_pdp_timeout", () => {
    const out = mapPdpFailure(
      new SdePdpError("timed out", "PDP_TIMEOUT", { latencyMs: 5000 }),
      baseReq,
      "shell"
    );
    assert.equal(out.decision, "deny");
    assert.ok(out.risk_signals.some((s) => s.code === "sde_pdp_timeout"));
  });

  it("evaluatePolicy denies when authorize throws", async () => {
    setAuthorizeFn(async () => {
      throw new SdePdpError("connection refused", "PDP_TRANSPORT_ERROR");
    });

    const result = await evaluatePolicy("read_file", { path: "x" }, {
      agent_id: "a",
      session_id: "s",
      model: "m",
      trusted_mode: false,
      environment: "dev",
      deployment_id: null,
    });

    assert.equal(result.decision, "deny");
    assert.ok(
      result.risk_signals.some((s) => s.code === "sde_pdp_transport_error")
    );
  });

  it("decide exercises PDP authorize and preserves mapped deny reason", async () => {
    setAuthorizeFn(async (body) => {
      const action = body.inputs.action_request as {
        tool_name: string;
        agent_id: string;
        trusted_mode: boolean;
      };
      // Prove outbound mapping still carries context into the mock.
      assert.equal(typeof action.agent_id, "string");
      assert.equal(typeof action.trusted_mode, "boolean");

      if (action.tool_name === "read_file") {
        return {
          decision: "allow",
          decision_hash: "h-allow",
          trace: { policy_variant: body.policy_variant },
        };
      }
      return {
        decision: "deny",
        deny_code: "TOOL_NOT_ALLOWED",
        deny_reason: "not covered",
        decision_hash: "h-deny",
        trace: { policy_variant: body.policy_variant },
      };
    });

    const response = await decide({
      tool_calls: [
        {
          id: "1",
          type: "function",
          function: { name: "read_file", arguments: "{}" },
        },
        {
          id: "2",
          type: "function",
          function: { name: "delete_file", arguments: "{}" },
        },
      ],
      context: {
        agent_id: "a",
        session_id: "s",
        model: "m",
        trusted_mode: false,
        environment: "dev",
        deployment_id: null,
      },
    });

    assert.equal(response.decisions[0]!.decision, "allow");
    assert.equal(response.decisions[1]!.decision, "deny");
    assert.match(response.decisions[1]!.reason, /TOOL_NOT_ALLOWED|not covered/);
    assert.equal(response.decisions[0]!.passport, null);
    assert.equal(response.decisions[1]!.passport, null);
  });
});
