/**
 * Dexgate Decision Execution Governance — locked interface contract v0.1
 *
 * Middleware performs no side effects: it only decides and records evidence.
 */

// ---------------------------------------------------------------------------
// Request
// ---------------------------------------------------------------------------

export interface ToolFunction {
  name: string;
  /** JSON-encoded argument object (stringified JSON). */
  arguments: string;
}

export interface ToolCall {
  id: string;
  type: "function";
  function: ToolFunction;
}

export type Environment = "dev" | "staging" | "production";

export interface DecisionContext {
  agent_id: string;
  session_id: string;
  model: string;
  trusted_mode: boolean;
  environment: Environment;
  deployment_id: string | null;
  /**
   * Optional SDE PDP decision SKU (e.g. openclaw.trusted_mode.authorize.v1).
   * Selection precedence: context.decision_sku (or context.sku) → env → OpenClaw default.
   * Omitted for backward compatibility.
   */
  decision_sku?: string;
  /**
   * Alias for decision_sku (same precedence). Prefer decision_sku when both are set.
   */
  sku?: string;
  /**
   * Optional SDE PDP policy_variant (e.g. guard-pro.v2026.02).
   * Selection precedence: context.policy_variant → env → default pack variant.
   */
  policy_variant?: string;
  /**
   * Optional SDE tenant id for entitlements / multi-tenant routing.
   * Precedence: context.tenant_id → env (SDE_PDP_TENANT_ID / TENANT_ID) → default.
   */
  tenant_id?: string;
  /**
   * Optional SDE gateway / host id for gateway and environment limits.
   * Precedence: context.gateway_id → env (SDE_PDP_GATEWAY_ID) → omitted.
   */
  gateway_id?: string;
}

export interface DecisionRequest {
  tool_calls: ToolCall[];
  context: DecisionContext;
}

// ---------------------------------------------------------------------------
// Response
// ---------------------------------------------------------------------------

export type DecisionOutcome = "allow" | "deny" | "constrain" | "escalate";

export interface RiskSignal {
  code: string;
  severity: "info" | "low" | "medium" | "high" | "critical";
  message: string;
}

export interface DecisionEvidence {
  /** Reconstructible proposal that was evaluated (tool name + parsed/raw args). */
  proposal: {
    tool_call_id: string;
    tool_name: string;
    arguments_raw: string;
    arguments_parsed: unknown | null;
    parse_error: string | null;
  };
  policy_version: string;
  evaluated_at: string; // ISO-8601
  risk_signals: RiskSignal[];
}

export interface ToolDecision {
  tool_call_id: string;
  decision: DecisionOutcome;
  reason: string;
  modified_arguments: Record<string, unknown> | null;
  /** Null in free/local mode (v0.1). */
  passport: string | null;
  evidence: DecisionEvidence;
}

export interface DecisionResponse {
  trace_id: string;
  decisions: ToolDecision[];
}

// ---------------------------------------------------------------------------
// Policy engine internals
// ---------------------------------------------------------------------------

export const POLICY_VERSION = "0.1.0-starter";

export interface PolicyEvaluation {
  decision: DecisionOutcome;
  reason: string;
  modified_arguments: Record<string, unknown> | null;
  risk_signals: RiskSignal[];
}
