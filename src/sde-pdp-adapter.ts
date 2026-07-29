/**
 * Bidirectional mapping between Dexgate DecisionRequest pieces and SDE PDP
 * AuthorizeRequest / authorize response.
 *
 * OpenClaw SKU (openclaw.trusted_mode.authorize.v1) — primary path this module
 * optimizes for:
 *
 *   {
 *     decision_sku, policy_variant, tenant_id, gateway_id, environment,
 *     inputs: {
 *       environment, gateway_id,
 *       action_request: {
 *         tool_name,          // pack primary key
 *         params,             // structured tool args
 *         path / targetPath,  // when present (passport target helpers)
 *         command,            // when present (shell / passport)
 *         origin: { … },      // origin metadata contract
 *         environment, trusted_mode, agent_id, session_id, model, deployment_id
 *       }
 *     }
 *   }
 *
 * Codex SKU path remains available when decision_sku is codex; new SKUs are
 * out of scope for this module.
 */

import type { DecisionContext, DecisionOutcome, RiskSignal } from "./types.js";
import {
  CODEX_DECISION_SKU,
  DEFAULT_POLICY_VARIANT,
  OPENCLAW_DECISION_SKU,
  loadPdpConfigFromEnv,
  type SdeAuthorizeRequest,
  type SdeAuthorizeResponse,
  type SdePdpConfig,
} from "./sde-pdp-client.js";

/** Where a selected SKU / policy_variant value came from (for evidence). */
export type SelectionSource = "context" | "env" | "default";

export interface ResolvedPdpSelection {
  decisionSku: string;
  policyVariant: string;
  tenantId: string;
  gatewayId?: string;
  /** Effective config with resolved sku/variant/tenant/gateway applied. */
  config: SdePdpConfig;
  decisionSkuSource: SelectionSource;
  policyVariantSource: SelectionSource;
  tenantIdSource: SelectionSource;
  gatewayIdSource: SelectionSource;
}

function firstNonEmpty(...values: Array<string | undefined | null>): string | undefined {
  for (const v of values) {
    if (typeof v === "string" && v.trim()) return v.trim();
  }
  return undefined;
}

/**
 * Resolve decision_sku with precedence:
 *   1. context.decision_sku (or context.sku alias)
 *   2. base config / env (SDE_PDP_SKU, SDE_PDP_DECISION_SKU via loadPdpConfigFromEnv)
 *   3. openclaw.trusted_mode.authorize.v1
 *
 * `source` is approximate: non-default base values are labeled "env"
 * (covers both process env and explicit pdpConfig overrides).
 */
export function resolveDecisionSku(
  context: DecisionContext,
  base: SdePdpConfig = loadPdpConfigFromEnv()
): { value: string; source: SelectionSource } {
  const fromContext = firstNonEmpty(context.decision_sku, context.sku);
  if (fromContext) return { value: fromContext, source: "context" };

  const fromBase = firstNonEmpty(base.decisionSku);
  if (fromBase && fromBase !== OPENCLAW_DECISION_SKU) {
    return { value: fromBase, source: "env" };
  }
  return {
    value: fromBase || OPENCLAW_DECISION_SKU,
    source: "default",
  };
}

/**
 * Resolve policy_variant with precedence:
 *   1. context.policy_variant
 *   2. base config / env (SDE_PDP_POLICY_VARIANT, POLICY_VARIANT)
 *   3. guard-pro.v2026.02
 */
export function resolvePolicyVariant(
  context: DecisionContext,
  base: SdePdpConfig = loadPdpConfigFromEnv()
): { value: string; source: SelectionSource } {
  const fromContext = firstNonEmpty(context.policy_variant);
  if (fromContext) return { value: fromContext, source: "context" };

  const fromBase = firstNonEmpty(base.policyVariant);
  if (fromBase && fromBase !== DEFAULT_POLICY_VARIANT) {
    return { value: fromBase, source: "env" };
  }
  return {
    value: fromBase || DEFAULT_POLICY_VARIANT,
    source: "default",
  };
}

/**
 * Resolve tenant_id: context → env/base → default trial-tenant.
 */
export function resolveTenantId(
  context: DecisionContext,
  base: SdePdpConfig = loadPdpConfigFromEnv()
): { value: string; source: SelectionSource } {
  const fromContext = firstNonEmpty(context.tenant_id);
  if (fromContext) return { value: fromContext, source: "context" };
  const fromBase = firstNonEmpty(base.tenantId);
  if (fromBase && fromBase !== "trial-tenant") {
    return { value: fromBase, source: "env" };
  }
  return { value: fromBase || "trial-tenant", source: "default" };
}

/**
 * Resolve gateway_id: context → env/base → undefined (omitted).
 */
export function resolveGatewayId(
  context: DecisionContext,
  base: SdePdpConfig = loadPdpConfigFromEnv()
): { value: string | undefined; source: SelectionSource } {
  const fromContext = firstNonEmpty(context.gateway_id);
  if (fromContext) return { value: fromContext, source: "context" };
  const fromBase = firstNonEmpty(base.gatewayId);
  if (fromBase) return { value: fromBase, source: "env" };
  return { value: undefined, source: "default" };
}

/**
 * Merge env/base config with per-request context selection.
 * Context always wins over env/default for SKU, policy_variant, tenant_id, gateway_id.
 */
export function resolvePdpSelection(
  context: DecisionContext,
  base: SdePdpConfig = loadPdpConfigFromEnv()
): ResolvedPdpSelection {
  const sku = resolveDecisionSku(context, base);
  const variant = resolvePolicyVariant(context, base);
  const tenant = resolveTenantId(context, base);
  const gateway = resolveGatewayId(context, base);
  return {
    decisionSku: sku.value,
    policyVariant: variant.value,
    tenantId: tenant.value,
    gatewayId: gateway.value,
    decisionSkuSource: sku.source,
    policyVariantSource: variant.source,
    tenantIdSource: tenant.source,
    gatewayIdSource: gateway.source,
    config: {
      ...base,
      decisionSku: sku.value,
      policyVariant: variant.value,
      tenantId: tenant.value,
      gatewayId: gateway.value,
    },
  };
}

/** True when the SKU should use the Codex inputs.request shape. */
export function isCodexSku(decisionSku: string): boolean {
  return decisionSku.trim() === CODEX_DECISION_SKU;
}

export interface MappedPdpOutcome {
  decision: DecisionOutcome;
  reason: string;
  modified_arguments: Record<string, unknown> | null;
  risk_signals: RiskSignal[];
  /** PDP policy variant / pack version for evidence enrichment. */
  pdp_policy_version: string | null;
  /** Raw PDP body retained for reconstructible evidence (not returned as passport). */
  pdp_raw: SdeAuthorizeResponse | null;
  /** Authorize payload that was (or would be) sent. */
  pdp_request: SdeAuthorizeRequest;
}

/** Adapter identity stamped into origin metadata. */
export const DEXGATE_ADAPTER_NAME = "dexgate-decision-middleware";
export const DEXGATE_ADAPTER_VERSION = "0.1.0";

// ---------------------------------------------------------------------------
// Request building
// ---------------------------------------------------------------------------

function asParams(args: unknown): Record<string, unknown> {
  if (args != null && typeof args === "object" && !Array.isArray(args)) {
    return { ...(args as Record<string, unknown>) };
  }
  if (args == null) return {};
  // Non-object JSON values (string/number/array) — keep reconstructible.
  return { value: args };
}

function firstString(
  obj: Record<string, unknown>,
  keys: string[]
): string | undefined {
  for (const key of keys) {
    const v = obj[key];
    if (typeof v === "string" && v.trim()) return v.trim();
  }
  return undefined;
}

/**
 * Build origin metadata using fields the SDE origin contract recognizes.
 * @see sde-enterprise/docs/origin_metadata_contract.md
 */
export function buildOriginMetadata(
  context: DecisionContext
): Record<string, unknown> {
  const origin: Record<string, unknown> = {
    agent: context.agent_id,
    agent_id: context.agent_id,
    session_id: context.session_id,
    model: context.model,
    environment: context.environment,
    trusted_mode: context.trusted_mode,
    adapter: DEXGATE_ADAPTER_NAME,
    adapter_version: DEXGATE_ADAPTER_VERSION,
  };

  if (context.deployment_id != null && context.deployment_id !== "") {
    origin.deployment_id = context.deployment_id;
    origin.deployment_environment = context.environment;
  }
  if (context.gateway_id != null && context.gateway_id !== "") {
    origin.gateway_id = context.gateway_id;
  }
  if (context.tenant_id != null && context.tenant_id !== "") {
    origin.tenant_id = context.tenant_id;
  }

  return origin;
}

/**
 * Build the OpenClaw `inputs.action_request` object with structured fields
 * the PDP pack and passport helpers already understand.
 */
export function buildOpenClawActionRequest(
  toolName: string,
  args: unknown,
  context: DecisionContext
): Record<string, unknown> {
  const name = typeof toolName === "string" ? toolName.trim() : "";
  const params = asParams(args);
  const origin = buildOriginMetadata(context);

  const path = firstString(params, [
    "path",
    "targetPath",
    "target_path",
    "file",
    "filename",
  ]);
  const command = firstString(params, [
    "command",
    "cmd",
    "script",
    "code",
    "input",
  ]);

  // Core pack fields first; then structured context the PDP/monitor scopes use.
  const action_request: Record<string, unknown> = {
    tool_name: name,
    // Alias used by some PDP helpers / passport fingerprinting.
    toolName: name,
    params,
    origin,
    environment: context.environment,
    trusted_mode: context.trusted_mode,
    agent_id: context.agent_id,
    session_id: context.session_id,
    model: context.model,
  };

  // Passport / target helpers look at top-level path and command.
  if (path !== undefined) {
    action_request.path = path;
    action_request.targetPath = path;
    action_request.target_path = path;
  }
  if (command !== undefined) {
    action_request.command = command;
  }

  if (context.deployment_id != null && context.deployment_id !== "") {
    action_request.deployment_id = context.deployment_id;
  } else {
    action_request.deployment_id = null;
  }

  return action_request;
}

function extractCommand(params: Record<string, unknown>): string {
  return firstString(params, ["command", "cmd", "script", "code", "input"]) ?? "";
}

/**
 * Build Codex `inputs.request` object (codex.trusted_mode.authorize.v1).
 * Shape matches SDE pack CodexTrustedModeAuthorize expectations.
 */
export function buildCodexRequest(
  toolName: string,
  args: unknown,
  context: DecisionContext
): Record<string, unknown> {
  const params = asParams(args);
  const origin = buildOriginMetadata(context);
  const name = typeof toolName === "string" ? toolName.trim() : "";
  const toolNameCodex = name.startsWith("functions.")
    ? name
    : name
      ? `functions.${name}`
      : "";

  const path = firstString(params, [
    "path",
    "targetPath",
    "target_path",
    "file",
    "filename",
  ]);

  const request: Record<string, unknown> = {
    runtime: "codex",
    toolName: toolNameCodex,
    command: extractCommand(params),
    environment: context.environment,
    origin,
    params,
    trusted_mode: context.trusted_mode,
    agent_id: context.agent_id,
    session_id: context.session_id,
    model: context.model,
  };

  if (path !== undefined) {
    request.path = path;
    request.targetPath = path;
  }
  if (context.deployment_id != null && context.deployment_id !== "") {
    request.deployment_id = context.deployment_id;
  } else {
    request.deployment_id = null;
  }

  return request;
}

/**
 * Build the SDE PDP authorize body from a single tool call + Dexgate context.
 *
 * SKU / policy_variant selection (context → env/base config → default).
 * Input shape:
 * - OpenClaw (default): inputs.action_request
 * - Codex: inputs.request
 */
export function buildAuthorizeRequest(
  toolName: string,
  args: unknown,
  context: DecisionContext,
  config: SdePdpConfig = loadPdpConfigFromEnv()
): SdeAuthorizeRequest {
  const selection = resolvePdpSelection(context, config);
  const decisionSku = selection.decisionSku;
  const policyVariant = selection.policyVariant;
  const tenantId = selection.tenantId;
  const gatewayId = selection.gatewayId;

  if (isCodexSku(decisionSku)) {
    const request = buildCodexRequest(toolName, args, context);
    return {
      decision_sku: decisionSku,
      policy_variant: policyVariant,
      tenant_id: tenantId,
      gateway_id: gatewayId ?? null,
      environment: context.environment,
      inputs: {
        request,
        environment: context.environment,
        ...(gatewayId ? { gateway_id: gatewayId } : {}),
      },
    };
  }

  // OpenClaw (default) and any other non-Codex SKU use action_request shape.
  const action_request = buildOpenClawActionRequest(toolName, args, context);

  return {
    decision_sku: decisionSku,
    policy_variant: policyVariant,
    tenant_id: tenantId,
    gateway_id: gatewayId ?? null,
    environment: context.environment,
    inputs: {
      action_request,
      environment: context.environment,
      ...(gatewayId ? { gateway_id: gatewayId } : {}),
    },
  };
}

// ---------------------------------------------------------------------------
// Response mapping
// ---------------------------------------------------------------------------

function constraintsList(value: unknown): unknown[] {
  return Array.isArray(value) ? value : [];
}

function formatConstraints(constraints: unknown[]): string {
  if (constraints.length === 0) return "";
  try {
    return JSON.stringify(constraints);
  } catch {
    return String(constraints.length);
  }
}

/**
 * Normalize PDP decision strings into Dexgate outcomes.
 * Unknown / empty → null (caller fail-closes to deny).
 */
export function normalizePdpDecision(
  raw: unknown
): DecisionOutcome | null {
  if (typeof raw !== "string") return null;
  const d = raw.trim().toLowerCase();
  if (d === "allow" || d === "deny" || d === "constrain" || d === "escalate") {
    return d;
  }
  // Occasional synonyms seen in adjacent systems — map conservatively.
  if (d === "allowed" || d === "permit" || d === "permitted") return "allow";
  if (d === "denied" || d === "block" || d === "blocked" || d === "refuse" || d === "refused") {
    return "deny";
  }
  if (d === "constrained" || d === "restrict" || d === "restricted") {
    return "constrain";
  }
  if (d === "escalation" || d === "pending_approval" || d === "requires_approval") {
    return "escalate";
  }
  return null;
}

function stringField(value: unknown): string | null {
  return typeof value === "string" && value.trim() ? value.trim() : null;
}

/**
 * Map an SDE PDP authorize response into a Dexgate PolicyEvaluation-shaped
 * outcome. Unclear / missing / partial decision → deny (fail closed).
 *
 * Passport is intentionally not propagated (free/local mode keeps null).
 * Constraints are reflected in reason + risk_signals; modified_arguments stays null.
 */
export function mapAuthorizeResponse(
  pdp: SdeAuthorizeResponse | null | undefined,
  pdpRequest: SdeAuthorizeRequest,
  toolName: string
): MappedPdpOutcome {
  const risk_signals: RiskSignal[] = [];

  // Completely missing / non-object body → fail closed.
  if (pdp == null || typeof pdp !== "object") {
    risk_signals.push({
      code: "sde_pdp_unclear_decision",
      severity: "critical",
      message: "PDP response is null or not an object.",
    });
    return {
      decision: "deny",
      reason: `Denied: SDE PDP returned an unusable response for tool "${toolName}" (default deny when unclear).`,
      modified_arguments: null,
      risk_signals,
      pdp_policy_version: pdpRequest.policy_variant,
      pdp_raw: null,
      pdp_request: pdpRequest,
    };
  }

  const trace =
    pdp.trace != null && typeof pdp.trace === "object"
      ? (pdp.trace as Record<string, unknown>)
      : {};

  const policyVariant =
    stringField(trace.policy_variant) || pdpRequest.policy_variant || null;
  const packVersion = stringField(trace.policy_pack_version);
  const denyCode = stringField(pdp.deny_code);
  const denyReason = stringField(pdp.deny_reason);
  const decisionHash =
    stringField(pdp.decision_hash) || stringField(trace.decision_hash);
  const constraints = constraintsList(pdp.constraints);

  // --- Reconstructible governance evidence ---
  if (policyVariant) {
    risk_signals.push({
      code: "sde_pdp_policy_variant",
      severity: "info",
      message: `SDE PDP policy_variant=${policyVariant}`,
    });
  }
  if (packVersion) {
    risk_signals.push({
      code: "sde_pdp_policy_pack_version",
      severity: "info",
      message: packVersion,
    });
  }
  if (decisionHash) {
    risk_signals.push({
      code: "sde_pdp_decision_hash",
      severity: "info",
      message: decisionHash,
    });
  }
  if (denyCode) {
    risk_signals.push({
      code: "sde_pdp_deny_code",
      severity: "high",
      message: denyCode,
    });
  }
  if (denyReason) {
    risk_signals.push({
      code: "sde_pdp_deny_reason",
      severity: "high",
      message: denyReason,
    });
  }
  if (typeof trace.blast_radius_score === "number") {
    risk_signals.push({
      code: "sde_pdp_blast_radius",
      severity: trace.blast_radius_score >= 50 ? "high" : "info",
      message: `blast_radius_score=${trace.blast_radius_score}`,
    });
  }
  if (stringField(trace.action_class)) {
    risk_signals.push({
      code: "sde_pdp_action_class",
      severity: "info",
      message: String(trace.action_class),
    });
  }
  if (stringField(trace.risk_classification_label)) {
    risk_signals.push({
      code: "sde_pdp_risk_classification",
      severity: "info",
      message: String(trace.risk_classification_label),
    });
  }
  if (Array.isArray(trace.governance_requirements) && trace.governance_requirements.length > 0) {
    risk_signals.push({
      code: "sde_pdp_governance_requirements",
      severity: "medium",
      message: JSON.stringify(trace.governance_requirements).slice(0, 500),
    });
  }
  if (pdp.enforcement_mode === "monitor" && pdp.enforcement_bypassed === true) {
    risk_signals.push({
      code: "sde_pdp_monitor_bypass",
      severity: "medium",
      message: `Monitor mode bypassed enforcement; would_have_decision=${String(
        pdp.would_have_decision ?? "unknown"
      )}${
        pdp.would_have_deny_code
          ? `; would_have_deny_code=${String(pdp.would_have_deny_code)}`
          : ""
      }`,
    });
  }
  if (constraints.length > 0) {
    risk_signals.push({
      code: "sde_pdp_constraints",
      severity: "low",
      message: formatConstraints(constraints).slice(0, 500),
    });
  }

  // --- Decision resolution (fail closed) ---
  let outcome = normalizePdpDecision(pdp.decision);

  // Partial response: no decision string, but deny_code/reason present → deny.
  if (!outcome && (denyCode || denyReason)) {
    outcome = "deny";
    risk_signals.push({
      code: "sde_pdp_partial_response",
      severity: "medium",
      message:
        "PDP omitted decision field but provided deny_code/deny_reason; treated as deny.",
    });
  }

  // allow + non-empty constraints → constrain (Dexgate outcome set).
  if (outcome === "allow" && constraints.length > 0) {
    outcome = "constrain";
    risk_signals.push({
      code: "sde_pdp_allow_with_constraints",
      severity: "info",
      message:
        "PDP decision was allow with constraints; mapped to Dexgate constrain.",
    });
  }

  if (!outcome) {
    risk_signals.push({
      code: "sde_pdp_unclear_decision",
      severity: "critical",
      message: `Unclear or missing PDP decision field: ${JSON.stringify(
        pdp.decision
      )}`,
    });
    risk_signals.push({
      code: "default_deny",
      severity: "high",
      message: "Fail closed: default deny when PDP decision is unclear.",
    });
    return {
      decision: "deny",
      reason: `Denied: SDE PDP returned an unclear decision for tool "${toolName}" (default deny when unclear).`,
      modified_arguments: null,
      risk_signals,
      pdp_policy_version: packVersion ?? policyVariant,
      pdp_raw: pdp,
      pdp_request: pdpRequest,
    };
  }

  risk_signals.push({
    code: "sde_pdp_mapped_decision",
    severity: "info",
    message: `mapped_decision=${outcome}; raw_decision=${JSON.stringify(
      pdp.decision
    )}`,
  });

  const pdpPolicyVersion = packVersion ?? policyVariant;

  if (outcome === "deny") {
    const detailParts: string[] = [];
    if (denyCode) detailParts.push(`[${denyCode}]`);
    if (denyReason) detailParts.push(denyReason);
    else if (!denyCode) detailParts.push("policy deny");
    const detail = detailParts.join(" ").trim();
    return {
      decision: "deny",
      reason: `Denied by SDE PDP for tool "${toolName}": ${detail}`,
      modified_arguments: null,
      risk_signals,
      pdp_policy_version: pdpPolicyVersion,
      pdp_raw: pdp,
      pdp_request: pdpRequest,
    };
  }

  if (outcome === "constrain") {
    const cSummary =
      constraints.length > 0
        ? `: ${formatConstraints(constraints).slice(0, 200)}`
        : "";
    return {
      decision: "constrain",
      reason: `Constrained by SDE PDP for tool "${toolName}" (${constraints.length} constraint(s))${cSummary}`,
      modified_arguments: null, // v0.1: surface via evidence only
      risk_signals,
      pdp_policy_version: pdpPolicyVersion,
      pdp_raw: pdp,
      pdp_request: pdpRequest,
    };
  }

  if (outcome === "escalate") {
    return {
      decision: "escalate",
      reason: `Escalated by SDE PDP for tool "${toolName}"${
        denyReason ? `: ${denyReason}` : ""
      }${denyCode ? ` [${denyCode}]` : ""}.`,
      modified_arguments: null,
      risk_signals,
      pdp_policy_version: pdpPolicyVersion,
      pdp_raw: pdp,
      pdp_request: pdpRequest,
    };
  }

  // allow
  return {
    decision: "allow",
    reason: `Allowed by SDE PDP for tool "${toolName}".`,
    modified_arguments: null,
    risk_signals,
    pdp_policy_version: pdpPolicyVersion,
    pdp_raw: pdp,
    pdp_request: pdpRequest,
  };
}

// ---------------------------------------------------------------------------
// Fail-closed transport mapping
// ---------------------------------------------------------------------------

/**
 * Map internal SdePdpError codes to evidence risk_signal codes.
 */
/**
 * Map internal SdePdpError codes to evidence risk_signal codes.
 * Primary operator-facing codes: timeout, transport, http, unclear_decision.
 */
export function pdpErrorToRiskSignalCode(pdpCode: string): string {
  switch (pdpCode) {
    case "PDP_TIMEOUT":
      return "sde_pdp_timeout";
    case "PDP_TRANSPORT_ERROR":
      return "sde_pdp_transport_error";
    case "PDP_HTTP_ERROR":
      return "sde_pdp_http_error";
    case "PDP_AUTH_FAILED":
      // Auth is still an HTTP client failure; keep distinct for operators.
      return "sde_pdp_http_error";
    case "PDP_INVALID_RESPONSE":
      // Unparseable / empty body → treat as unclear decision path for evidence.
      return "sde_pdp_unclear_decision";
    case "PDP_URL_MISSING":
    case "PDP_URL_INVALID":
      return "sde_pdp_transport_error";
    default:
      return "sde_pdp_transport_error";
  }
}

/**
 * Fail-closed mapping when the PDP call fails or returns unusable data.
 * Always deny; attach a typed risk_signal (timeout / transport / …).
 */
export function mapPdpFailure(
  error: unknown,
  pdpRequest: SdeAuthorizeRequest,
  toolName: string
): MappedPdpOutcome {
  const code =
    error &&
    typeof error === "object" &&
    "code" in error &&
    typeof (error as { code: unknown }).code === "string"
      ? (error as { code: string }).code
      : "PDP_ERROR";
  const message =
    error instanceof Error ? error.message : String(error ?? "unknown error");
  const signalCode = pdpErrorToRiskSignalCode(code);
  const latencyMs =
    error &&
    typeof error === "object" &&
    "latencyMs" in error &&
    typeof (error as { latencyMs: unknown }).latencyMs === "number"
      ? (error as { latencyMs: number }).latencyMs
      : undefined;

  const attempts =
    error &&
    typeof error === "object" &&
    "attempts" in error &&
    typeof (error as { attempts: unknown }).attempts === "number"
      ? (error as { attempts: number }).attempts
      : undefined;

  const detailParts = [`${code}: ${message}`];
  if (latencyMs != null) detailParts.push(`latency_ms=${latencyMs}`);
  if (attempts != null) detailParts.push(`attempts=${attempts}`);

  const risk_signals: RiskSignal[] = [
    {
      code: signalCode,
      severity: "critical",
      message: detailParts.join("; "),
    },
    {
      code: "default_deny",
      severity: "high",
      message:
        "Fail closed: default deny when PDP is unavailable, times out, or returns an unusable result.",
    },
  ];

  return {
    decision: "deny",
    reason: `Denied: SDE PDP call failed for tool "${toolName}" (${code}): ${message}`,
    modified_arguments: null,
    risk_signals,
    pdp_policy_version: pdpRequest.policy_variant,
    pdp_raw: null,
    pdp_request: pdpRequest,
  };
}
