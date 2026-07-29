/**
 * Dexgate decision middleware — decide + evidence.
 *
 * Contract v0.1:
 * - Every tool call gets exactly one decision.
 * - Default when unclear = deny.
 * - passport is always null (free/local mode).
 * - evidence is always present and reconstructible.
 *
 * Policy evaluation delegates to the SDE Enterprise PDP (HTTP).
 * This module performs no local persistence or Passport issuance.
 */

import { randomUUID } from "node:crypto";
import { evaluatePolicy } from "./policy.js";
import type {
  DecisionContext,
  DecisionRequest,
  DecisionResponse,
  Environment,
  ToolCall,
  ToolDecision,
} from "./types.js";
import { POLICY_VERSION } from "./types.js";

function isEnvironment(value: unknown): value is Environment {
  return value === "dev" || value === "staging" || value === "production";
}

function parseArguments(raw: string): {
  parsed: unknown | null;
  parse_error: string | null;
} {
  if (raw == null || raw === "") {
    return { parsed: {}, parse_error: null };
  }
  if (typeof raw !== "string") {
    return {
      parsed: null,
      parse_error: "arguments must be a JSON string",
    };
  }
  try {
    return { parsed: JSON.parse(raw) as unknown, parse_error: null };
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    return { parsed: null, parse_error: message };
  }
}

/**
 * Validate and normalize request shape. Returns structured issues; does not throw
 * for per-tool problems — those become deny decisions. Throws only when the
 * request is not a usable DecisionRequest at all.
 */
export function validateRequest(input: unknown): {
  ok: true;
  request: DecisionRequest;
} | {
  ok: false;
  error: string;
} {
  if (input == null || typeof input !== "object") {
    return { ok: false, error: "Request must be a non-null object." };
  }

  const body = input as Record<string, unknown>;

  if (!Array.isArray(body.tool_calls)) {
    return { ok: false, error: "Request.tool_calls must be an array." };
  }

  if (body.context == null || typeof body.context !== "object") {
    return { ok: false, error: "Request.context must be an object." };
  }

  const ctx = body.context as Record<string, unknown>;

  if (typeof ctx.agent_id !== "string" || !ctx.agent_id) {
    return { ok: false, error: "context.agent_id must be a non-empty string." };
  }
  if (typeof ctx.session_id !== "string" || !ctx.session_id) {
    return { ok: false, error: "context.session_id must be a non-empty string." };
  }
  if (typeof ctx.model !== "string" || !ctx.model) {
    return { ok: false, error: "context.model must be a non-empty string." };
  }
  if (typeof ctx.trusted_mode !== "boolean") {
    return { ok: false, error: "context.trusted_mode must be a boolean." };
  }
  if (!isEnvironment(ctx.environment)) {
    return {
      ok: false,
      error: 'context.environment must be "dev" | "staging" | "production".',
    };
  }
  if (ctx.deployment_id !== null && typeof ctx.deployment_id !== "string") {
    return {
      ok: false,
      error: "context.deployment_id must be a string or null.",
    };
  }

  // Optional PDP selection / routing fields (backward compatible when omitted).
  for (const key of [
    "decision_sku",
    "sku",
    "policy_variant",
    "tenant_id",
    "gateway_id",
  ] as const) {
    if (ctx[key] !== undefined && ctx[key] !== null) {
      if (typeof ctx[key] !== "string" || !(ctx[key] as string).trim()) {
        return {
          ok: false,
          error: `context.${key} must be a non-empty string when provided.`,
        };
      }
    }
  }

  const context: DecisionContext = {
    agent_id: ctx.agent_id,
    session_id: ctx.session_id,
    model: ctx.model,
    trusted_mode: ctx.trusted_mode,
    environment: ctx.environment,
    deployment_id: ctx.deployment_id as string | null,
  };

  if (typeof ctx.decision_sku === "string" && ctx.decision_sku.trim()) {
    context.decision_sku = ctx.decision_sku.trim();
  }
  if (typeof ctx.sku === "string" && ctx.sku.trim()) {
    context.sku = ctx.sku.trim();
  }
  if (typeof ctx.policy_variant === "string" && ctx.policy_variant.trim()) {
    context.policy_variant = ctx.policy_variant.trim();
  }
  if (typeof ctx.tenant_id === "string" && ctx.tenant_id.trim()) {
    context.tenant_id = ctx.tenant_id.trim();
  }
  if (typeof ctx.gateway_id === "string" && ctx.gateway_id.trim()) {
    context.gateway_id = ctx.gateway_id.trim();
  }

  // Normalize tool_calls; malformed individual entries become synthetic deniable calls
  const tool_calls: ToolCall[] = body.tool_calls.map((tc, index) => {
    if (tc == null || typeof tc !== "object") {
      return {
        id: `malformed-${index}`,
        type: "function" as const,
        function: { name: "", arguments: "{}" },
      };
    }
    const t = tc as Record<string, unknown>;
    const fn =
      t.function != null && typeof t.function === "object"
        ? (t.function as Record<string, unknown>)
        : {};
    return {
      id: typeof t.id === "string" && t.id ? t.id : `missing-id-${index}`,
      type: "function" as const,
      function: {
        name: typeof fn.name === "string" ? fn.name : "",
        arguments:
          typeof fn.arguments === "string"
            ? fn.arguments
            : fn.arguments != null
              ? JSON.stringify(fn.arguments)
              : "{}",
      },
    };
  });

  return {
    ok: true,
    request: { tool_calls, context },
  };
}

async function decideOne(
  toolCall: ToolCall,
  context: DecisionContext,
  evaluatedAt: string
): Promise<ToolDecision> {
  const { parsed, parse_error } = parseArguments(toolCall.function.arguments);
  const toolName = toolCall.function.name;

  // Invalid JSON arguments → deny (unclear)
  if (parse_error) {
    return {
      tool_call_id: toolCall.id,
      decision: "deny",
      reason: `Denied: tool arguments are not valid JSON (${parse_error}).`,
      modified_arguments: null,
      passport: null,
      evidence: {
        proposal: {
          tool_call_id: toolCall.id,
          tool_name: toolName,
          arguments_raw: toolCall.function.arguments,
          arguments_parsed: null,
          parse_error,
        },
        policy_version: POLICY_VERSION,
        evaluated_at: evaluatedAt,
        risk_signals: [
          {
            code: "invalid_arguments_json",
            severity: "high",
            message: parse_error,
          },
        ],
      },
    };
  }

  const evaluation = await evaluatePolicy(toolName, parsed, context);

  return {
    tool_call_id: toolCall.id,
    decision: evaluation.decision,
    reason: evaluation.reason,
    modified_arguments: evaluation.modified_arguments,
    passport: null, // free/local mode — v0.1 (PDP passport not surfaced here)
    evidence: {
      proposal: {
        tool_call_id: toolCall.id,
        tool_name: toolName,
        arguments_raw: toolCall.function.arguments,
        arguments_parsed: parsed,
        parse_error: null,
      },
      policy_version: POLICY_VERSION,
      evaluated_at: evaluatedAt,
      risk_signals: evaluation.risk_signals,
    },
  };
}

/**
 * Core entry point: evaluate all tool calls and return a DecisionResponse.
 *
 * - Generates a fresh `trace_id` per request.
 * - Emits exactly one decision per tool call.
 * - Async: each tool call is authorized via the SDE PDP.
 * - On request-level malformation, throws so callers can return HTTP 400.
 *   Use {@link decideSafe} if you want a deny-all style envelope for bad input.
 */
export async function decide(
  input: DecisionRequest | unknown
): Promise<DecisionResponse> {
  const validated = validateRequest(input);
  if (!validated.ok) {
    throw new DecisionRequestError(validated.error);
  }

  const { request } = validated;
  const trace_id = randomUUID();
  const evaluated_at = new Date().toISOString();

  const decisions = await Promise.all(
    request.tool_calls.map((tc) => decideOne(tc, request.context, evaluated_at))
  );

  return { trace_id, decisions };
}

/**
 * Safe variant for malformed top-level requests: never throws.
 * Returns a synthetic deny decision so every call still yields reconstructible
 * evidence, with a generated trace_id.
 */
export async function decideSafe(input: unknown): Promise<DecisionResponse> {
  const validated = validateRequest(input);
  const trace_id = randomUUID();
  const evaluated_at = new Date().toISOString();

  if (!validated.ok) {
    return {
      trace_id,
      decisions: [
        {
          tool_call_id: "request",
          decision: "deny",
          reason: `Denied: malformed request — ${validated.error}`,
          modified_arguments: null,
          passport: null,
          evidence: {
            proposal: {
              tool_call_id: "request",
              tool_name: "",
              arguments_raw: "",
              arguments_parsed: null,
              parse_error: validated.error,
            },
            policy_version: POLICY_VERSION,
            evaluated_at,
            risk_signals: [
              {
                code: "malformed_request",
                severity: "critical",
                message: validated.error,
              },
            ],
          },
        },
      ],
    };
  }

  return decide(validated.request);
}

export class DecisionRequestError extends Error {
  readonly code = "MALFORMED_REQUEST";

  constructor(message: string) {
    super(message);
    this.name = "DecisionRequestError";
  }
}
