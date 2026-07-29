/**
 * SKU / policy_variant selection and Codex-shaped mapping tests.
 */

import assert from "node:assert/strict";
import { afterEach, describe, it } from "node:test";
import {
  CODEX_DECISION_SKU,
  DEFAULT_POLICY_VARIANT,
  OPENCLAW_DECISION_SKU,
  buildAuthorizeRequest,
  buildCodexRequest,
  decide,
  evaluatePolicy,
  isCodexSku,
  resolveDecisionSku,
  resolvePdpSelection,
  resolvePolicyVariant,
  setAuthorizeFn,
  validateRequest,
  type DecisionContext,
  type SdePdpConfig,
} from "../src/index.ts";

const baseCtx: DecisionContext = {
  agent_id: "agent-1",
  session_id: "sess-1",
  model: "grok",
  trusted_mode: false,
  environment: "dev",
  deployment_id: null,
};

const openClawBase: SdePdpConfig = {
  authorizeUrl: "http://127.0.0.1:8001/v1/authorize",
  tenantId: "trial-tenant",
  policyVariant: DEFAULT_POLICY_VARIANT,
  decisionSku: OPENCLAW_DECISION_SKU,
  timeoutMs: 1000,
};

const codexEnvBase: SdePdpConfig = {
  ...openClawBase,
  decisionSku: CODEX_DECISION_SKU,
  policyVariant: "codex-guard.v0.1.0",
};

afterEach(() => {
  setAuthorizeFn(null);
});

describe("resolveDecisionSku precedence", () => {
  it("defaults to openclaw when context and base are default", () => {
    const r = resolveDecisionSku(baseCtx, openClawBase);
    assert.equal(r.value, OPENCLAW_DECISION_SKU);
    assert.equal(r.source, "default");
  });

  it("uses base/env SKU when context omits sku", () => {
    const r = resolveDecisionSku(baseCtx, codexEnvBase);
    assert.equal(r.value, CODEX_DECISION_SKU);
    assert.equal(r.source, "env");
  });

  it("context.decision_sku wins over env base", () => {
    const r = resolveDecisionSku(
      { ...baseCtx, decision_sku: OPENCLAW_DECISION_SKU },
      codexEnvBase
    );
    assert.equal(r.value, OPENCLAW_DECISION_SKU);
    assert.equal(r.source, "context");
  });

  it("context.sku alias works; decision_sku preferred when both set", () => {
    const alias = resolveDecisionSku(
      { ...baseCtx, sku: CODEX_DECISION_SKU },
      openClawBase
    );
    assert.equal(alias.value, CODEX_DECISION_SKU);
    assert.equal(alias.source, "context");

    const both = resolveDecisionSku(
      {
        ...baseCtx,
        decision_sku: OPENCLAW_DECISION_SKU,
        sku: CODEX_DECISION_SKU,
      },
      openClawBase
    );
    assert.equal(both.value, OPENCLAW_DECISION_SKU);
  });
});

describe("resolvePolicyVariant precedence", () => {
  it("defaults to guard-pro when unset", () => {
    const r = resolvePolicyVariant(baseCtx, openClawBase);
    assert.equal(r.value, DEFAULT_POLICY_VARIANT);
    assert.equal(r.source, "default");
  });

  it("uses base/env variant when context omits it", () => {
    const r = resolvePolicyVariant(baseCtx, codexEnvBase);
    assert.equal(r.value, "codex-guard.v0.1.0");
    assert.equal(r.source, "env");
  });

  it("context.policy_variant wins over env base", () => {
    const r = resolvePolicyVariant(
      { ...baseCtx, policy_variant: "custom-pack.v1" },
      codexEnvBase
    );
    assert.equal(r.value, "custom-pack.v1");
    assert.equal(r.source, "context");
  });
});

describe("resolvePdpSelection + buildAuthorizeRequest shapes", () => {
  it("openclaw default builds action_request shape (backward compatible)", () => {
    const body = buildAuthorizeRequest(
      "read_file",
      { path: "README.md" },
      baseCtx,
      openClawBase
    );
    assert.equal(body.decision_sku, OPENCLAW_DECISION_SKU);
    assert.equal(body.policy_variant, DEFAULT_POLICY_VARIANT);
    assert.ok(body.inputs.action_request);
    assert.equal(
      (body.inputs.action_request as { tool_name: string }).tool_name,
      "read_file"
    );
    assert.equal(body.inputs.request, undefined);
  });

  it("codex context builds inputs.request shape with functions.* toolName", () => {
    const ctx: DecisionContext = {
      ...baseCtx,
      decision_sku: CODEX_DECISION_SKU,
      policy_variant: "codex-guard.v0.1.0",
      model: "codex",
    };
    const body = buildAuthorizeRequest(
      "shell_command",
      { command: "Get-Content README.md" },
      ctx,
      openClawBase // base is openclaw; context must win
    );

    assert.equal(body.decision_sku, CODEX_DECISION_SKU);
    assert.equal(body.policy_variant, "codex-guard.v0.1.0");
    assert.ok(body.inputs.request, "codex uses inputs.request");
    assert.equal(body.inputs.action_request, undefined);

    const req = body.inputs.request as Record<string, unknown>;
    assert.equal(req.runtime, "codex");
    assert.equal(req.toolName, "functions.shell_command");
    assert.equal(req.command, "Get-Content README.md");
    assert.equal(req.environment, "dev");
    assert.equal(req.trusted_mode, false);
    assert.ok(req.origin);
  });

  it("buildCodexRequest preserves functions. prefix when already present", () => {
    const req = buildCodexRequest(
      "functions.apply_patch",
      { path: "a.ts" },
      baseCtx
    );
    assert.equal(req.toolName, "functions.apply_patch");
    assert.equal(req.path, "a.ts");
    assert.equal(req.targetPath, "a.ts");
  });

  it("isCodexSku detects only the codex authorize SKU", () => {
    assert.equal(isCodexSku(CODEX_DECISION_SKU), true);
    assert.equal(isCodexSku(OPENCLAW_DECISION_SKU), false);
    assert.equal(isCodexSku("other.sku"), false);
  });

  it("env-level codex base without context still uses codex shape", () => {
    const body = buildAuthorizeRequest(
      "apply_patch",
      { path: "x.ts" },
      baseCtx,
      codexEnvBase
    );
    assert.equal(body.decision_sku, CODEX_DECISION_SKU);
    assert.ok(body.inputs.request);
    assert.equal(
      (body.inputs.request as { toolName: string }).toolName,
      "functions.apply_patch"
    );
  });
});

describe("validateRequest accepts optional selection fields", () => {
  it("accepts decision_sku and policy_variant on context", () => {
    const result = validateRequest({
      tool_calls: [],
      context: {
        agent_id: "a",
        session_id: "s",
        model: "m",
        trusted_mode: false,
        environment: "dev",
        deployment_id: null,
        decision_sku: CODEX_DECISION_SKU,
        policy_variant: "codex-guard.v0.1.0",
      },
    });
    assert.equal(result.ok, true);
    if (result.ok) {
      assert.equal(result.request.context.decision_sku, CODEX_DECISION_SKU);
      assert.equal(result.request.context.policy_variant, "codex-guard.v0.1.0");
    }
  });

  it("accepts optional tenant_id and gateway_id without requiring them", () => {
    const withIds = validateRequest({
      tool_calls: [],
      context: {
        agent_id: "a",
        session_id: "s",
        model: "m",
        trusted_mode: false,
        environment: "dev",
        deployment_id: null,
        tenant_id: "acme",
        gateway_id: "gw-1",
      },
    });
    assert.equal(withIds.ok, true);
    if (withIds.ok) {
      assert.equal(withIds.request.context.tenant_id, "acme");
      assert.equal(withIds.request.context.gateway_id, "gw-1");
    }

    const without = validateRequest({
      tool_calls: [],
      context: {
        agent_id: "a",
        session_id: "s",
        model: "m",
        trusted_mode: false,
        environment: "dev",
        deployment_id: null,
      },
    });
    assert.equal(without.ok, true);
    if (without.ok) {
      assert.equal(without.request.context.tenant_id, undefined);
      assert.equal(without.request.context.gateway_id, undefined);
    }
  });

  it("rejects empty decision_sku when provided", () => {
    const result = validateRequest({
      tool_calls: [],
      context: {
        agent_id: "a",
        session_id: "s",
        model: "m",
        trusted_mode: false,
        environment: "dev",
        deployment_id: null,
        decision_sku: "   ",
      },
    });
    assert.equal(result.ok, false);
  });

  it("omitted sku remains undefined (backward compatible)", () => {
    const result = validateRequest({
      tool_calls: [],
      context: {
        agent_id: "a",
        session_id: "s",
        model: "m",
        trusted_mode: false,
        environment: "dev",
        deployment_id: null,
      },
    });
    assert.equal(result.ok, true);
    if (result.ok) {
      assert.equal(result.request.context.decision_sku, undefined);
      assert.equal(result.request.context.policy_variant, undefined);
    }
  });
});

describe("decide end-to-end with SKU selection", () => {
  it("forwards context SKU/variant to PDP authorize body", async () => {
    let seenSku = "";
    let seenVariant = "";
    let seenShape: "request" | "action_request" | "none" = "none";

    setAuthorizeFn(async (body) => {
      seenSku = body.decision_sku;
      seenVariant = body.policy_variant;
      if (body.inputs.request) seenShape = "request";
      else if (body.inputs.action_request) seenShape = "action_request";
      return {
        decision: "allow",
        decision_hash: "sku-test",
        trace: {
          decision_sku: body.decision_sku,
          policy_variant: body.policy_variant,
        },
      };
    });

    const response = await decide({
      tool_calls: [
        {
          id: "1",
          type: "function",
          function: {
            name: "shell_command",
            arguments: JSON.stringify({ command: "echo hi" }),
          },
        },
      ],
      context: {
        ...baseCtx,
        decision_sku: CODEX_DECISION_SKU,
        policy_variant: "codex-guard.v0.1.0",
      },
    });

    assert.equal(seenSku, CODEX_DECISION_SKU);
    assert.equal(seenVariant, "codex-guard.v0.1.0");
    assert.equal(seenShape, "request");
    assert.equal(response.decisions[0]!.decision, "allow");
    assert.ok(
      response.decisions[0]!.evidence.risk_signals.some(
        (s) => s.code === "sde_pdp_selection" && s.message.includes("sku_source=context")
      )
    );
  });

  it("without context sku uses openclaw action_request (compat)", async () => {
    let seenShape: "request" | "action_request" | "none" = "none";
    setAuthorizeFn(async (body) => {
      if (body.inputs.request) seenShape = "request";
      else if (body.inputs.action_request) seenShape = "action_request";
      assert.equal(body.decision_sku, OPENCLAW_DECISION_SKU);
      return { decision: "allow", decision_hash: "compat" };
    });

    // Pass explicit default pdpConfig so ambient process env cannot force Codex.
    await evaluatePolicy("read_file", {}, baseCtx, { pdpConfig: openClawBase });

    assert.equal(seenShape, "action_request");
  });
});

describe("resolvePdpSelection combined", () => {
  it("returns effective config with context overrides applied", () => {
    const sel = resolvePdpSelection(
      {
        ...baseCtx,
        decision_sku: CODEX_DECISION_SKU,
        policy_variant: "codex-guard.v0.1.0",
        tenant_id: "acme-corp",
        gateway_id: "gw-edge-3",
      },
      openClawBase
    );
    assert.equal(sel.decisionSku, CODEX_DECISION_SKU);
    assert.equal(sel.policyVariant, "codex-guard.v0.1.0");
    assert.equal(sel.tenantId, "acme-corp");
    assert.equal(sel.gatewayId, "gw-edge-3");
    assert.equal(sel.config.decisionSku, CODEX_DECISION_SKU);
    assert.equal(sel.config.policyVariant, "codex-guard.v0.1.0");
    assert.equal(sel.config.tenantId, "acme-corp");
    assert.equal(sel.config.gatewayId, "gw-edge-3");
    assert.equal(sel.decisionSkuSource, "context");
    assert.equal(sel.policyVariantSource, "context");
    assert.equal(sel.tenantIdSource, "context");
    assert.equal(sel.gatewayIdSource, "context");
  });
});
