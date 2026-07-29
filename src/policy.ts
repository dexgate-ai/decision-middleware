/**
 * Dexgate policy evaluation — delegates to the SDE Enterprise PDP.
 *
 * Rules of engagement:
 * - Default when unclear or PDP failure = deny (fail closed).
 * - passport remains null at the Dexgate contract layer (v0.1; not free-mode-only).
 * - SKU / policy_variant: context → env → defaults (OpenClaw + guard-pro).
 * - No Passport issuance in this package; no persistence.
 */

import type { DecisionContext, PolicyEvaluation, RiskSignal } from "./types.js";
import {
  authorizeWithPdp,
  loadPdpConfigFromEnv,
  type SdePdpConfig,
} from "./sde-pdp-client.js";
import {
  buildAuthorizeRequest,
  mapAuthorizeResponse,
  mapPdpFailure,
  resolvePdpSelection,
} from "./sde-pdp-adapter.js";

export interface EvaluatePolicyOptions {
  /** Override env-derived PDP config (tests / custom wiring). Context still wins for sku/variant. */
  pdpConfig?: SdePdpConfig;
}

/**
 * Evaluate a single tool call via the SDE PDP.
 *
 * Async because the real PDP is an HTTP service. Inject a mock authorize
 * function via {@link setAuthorizeFn} from `./sde-pdp-client.js` in tests.
 */
export async function evaluatePolicy(
  toolName: string,
  args: unknown,
  context: DecisionContext,
  options: EvaluatePolicyOptions = {}
): Promise<PolicyEvaluation> {
  const risk_signals: RiskSignal[] = [];

  if (!toolName || typeof toolName !== "string" || !toolName.trim()) {
    return {
      decision: "deny",
      reason: "Denied: missing or empty tool name (default deny when unclear).",
      modified_arguments: null,
      risk_signals: [
        {
          code: "malformed_tool_name",
          severity: "high",
          message: "Tool name is missing, empty, or not a string.",
        },
      ],
    };
  }

  const baseConfig = options.pdpConfig ?? loadPdpConfigFromEnv();
  const selection = resolvePdpSelection(context, baseConfig);
  const config = selection.config;
  const pdpRequest = buildAuthorizeRequest(toolName, args, context, baseConfig);

  risk_signals.push({
    code: "sde_pdp_request",
    severity: "info",
    message: `decision_sku=${pdpRequest.decision_sku}; policy_variant=${pdpRequest.policy_variant}; tenant_id=${String(
      pdpRequest.tenant_id
    )}; gateway_id=${String(pdpRequest.gateway_id ?? "")}; environment=${String(
      pdpRequest.environment
    )}; tool=${toolName}`,
  });
  risk_signals.push({
    code: "sde_pdp_selection",
    severity: "info",
    message: `sku_source=${selection.decisionSkuSource}; variant_source=${selection.policyVariantSource}; tenant_source=${selection.tenantIdSource}; gateway_source=${selection.gatewayIdSource}`,
  });

  // Forward context semantics that SDE supports natively / via origin metadata.
  if (context.trusted_mode) {
    risk_signals.push({
      code: "trusted_mode_forwarded",
      severity: "info",
      message:
        "trusted_mode=true forwarded to SDE PDP origin/action metadata (monitor/approval semantics are PDP-side).",
    });
  }
  if (context.deployment_id != null) {
    risk_signals.push({
      code: "deployment_id_forwarded",
      severity: "info",
      message: `deployment_id=${context.deployment_id} forwarded to SDE PDP origin.`,
    });
  }

  try {
    const pdpResponse = await authorizeWithPdp(pdpRequest, config);
    const mapped = mapAuthorizeResponse(pdpResponse, pdpRequest, toolName);

    return {
      decision: mapped.decision,
      reason: mapped.reason,
      modified_arguments: mapped.modified_arguments,
      risk_signals: [...risk_signals, ...mapped.risk_signals],
    };
  } catch (err) {
    const mapped = mapPdpFailure(err, pdpRequest, toolName);
    return {
      decision: mapped.decision,
      reason: mapped.reason,
      modified_arguments: mapped.modified_arguments,
      risk_signals: [...risk_signals, ...mapped.risk_signals],
    };
  }
}

// Re-export injection point for tests and advanced wiring.
export {
  setAuthorizeFn,
  loadPdpConfigFromEnv,
  SdePdpError,
  assertValidAuthorizeUrl,
  DEFAULT_PDP_TIMEOUT_MS,
  DEFAULT_PDP_AUTHORIZE_URL,
  MAX_PDP_ATTEMPTS,
  OPENCLAW_DECISION_SKU,
  CODEX_DECISION_SKU,
  DEFAULT_POLICY_VARIANT,
  SUPPORTED_DECISION_SKUS,
  httpAuthorize,
  isRetriablePdpError,
  clampTimeoutMs,
} from "./sde-pdp-client.js";
export type {
  SdePdpConfig,
  AuthorizeFn,
  SdeAuthorizeRequest,
  SdeAuthorizeResponse,
} from "./sde-pdp-client.js";
