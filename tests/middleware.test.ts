/**
 * Contract v0.1 test cases for Dexgate decision middleware.
 *
 * Policy path is the SDE PDP (HTTP). These tests inject a mock authorize
 * function so outcomes are deterministic without a live PDP process.
 */

import assert from "node:assert/strict";
import { afterEach, describe, it } from "node:test";
import {
  decide,
  decideSafe,
  DecisionRequestError,
  POLICY_VERSION,
  setAuthorizeFn,
  type DecisionRequest,
  type DecisionResponse,
  type SdeAuthorizeRequest,
  type SdeAuthorizeResponse,
} from "../src/index.ts";

function baseContext(
  overrides: Partial<DecisionRequest["context"]> = {}
): DecisionRequest["context"] {
  return {
    agent_id: "agent-1",
    session_id: "sess-1",
    model: "grok-test",
    trusted_mode: false,
    environment: "dev",
    deployment_id: null,
    ...overrides,
  };
}

function toolCall(
  id: string,
  name: string,
  args: Record<string, unknown> | string = {}
) {
  return {
    id,
    type: "function" as const,
    function: {
      name,
      arguments:
        typeof args === "string" ? args : JSON.stringify(args),
    },
  };
}

function assertContractShape(response: DecisionResponse, expectedCount: number) {
  assert.equal(typeof response.trace_id, "string");
  assert.ok(response.trace_id.length > 0, "trace_id must be non-empty");
  assert.equal(response.decisions.length, expectedCount);

  for (const d of response.decisions) {
    assert.equal(typeof d.tool_call_id, "string");
    assert.ok(
      ["allow", "deny", "constrain", "escalate"].includes(d.decision),
      `invalid decision: ${d.decision}`
    );
    assert.equal(typeof d.reason, "string");
    assert.ok(d.reason.length > 0);
    assert.equal(d.passport, null, "passport must be null in free/local mode");
    assert.ok(d.evidence, "evidence must always be present");
    assert.equal(d.evidence.policy_version, POLICY_VERSION);
    assert.equal(typeof d.evidence.evaluated_at, "string");
    assert.ok(Array.isArray(d.evidence.risk_signals));
    assert.ok(d.evidence.proposal);
    assert.equal(typeof d.evidence.proposal.tool_name, "string");
    assert.equal(typeof d.evidence.proposal.arguments_raw, "string");
  }
}

/** Scenario-based mock PDP used by contract tests. */
function installScenarioPdp(): {
  calls: SdeAuthorizeRequest[];
} {
  const calls: SdeAuthorizeRequest[] = [];

  setAuthorizeFn(async (body) => {
    calls.push(body);
    const action =
      (body.inputs.action_request as Record<string, unknown> | undefined) ??
      (body.inputs.request as Record<string, unknown> | undefined) ??
      {};
    const toolName = String(
      action.tool_name ?? action.toolName ?? ""
    ).toLowerCase();
    const origin =
      action.origin != null && typeof action.origin === "object"
        ? (action.origin as Record<string, unknown>)
        : {};
    const trusted =
      action.trusted_mode === true ||
      origin.trusted_mode === true ||
      body.inputs.trusted_mode === true;
    const environment = String(
      body.environment ?? action.environment ?? origin.environment ?? ""
    ).toLowerCase();

    // --- scenario rules mirroring prior starter-policy coverage ---
    if (!toolName) {
      return {
        decision: "deny",
        deny_code: "MALFORMED_TOOL",
        deny_reason: "missing tool name",
        trace: { policy_variant: body.policy_variant },
      } satisfies SdeAuthorizeResponse;
    }

    // Read-only tools → allow
    if (
      toolName === "read_file" ||
      toolName === "list_dir" ||
      toolName === "grep" ||
      toolName.startsWith("functions.read")
    ) {
      return {
        decision: "allow",
        decision_hash: "mock-hash-allow",
        trace: {
          policy_variant: body.policy_variant,
          policy_pack_version: "mock-pack",
          tool_name: toolName,
        },
      };
    }

    // Production mutations blocked unless trusted_mode
    const mutationTools = new Set([
      "apply_patch",
      "write_file",
      "shell",
      "execute_shell",
      "functions.apply_patch",
      "functions.shell_command",
    ]);
    const isMutation =
      mutationTools.has(toolName) ||
      toolName.includes("apply_patch") ||
      toolName.includes("shell");

    if (environment === "production" && isMutation) {
      if (trusted) {
        return {
          decision: "allow",
          decision_hash: "mock-hash-trusted",
          trace: {
            policy_variant: body.policy_variant,
            tool_name: toolName,
            trusted_mode: true,
          },
        };
      }
      return {
        decision: "deny",
        deny_code: "PRODUCTION_MUTATION_BLOCKED",
        deny_reason: "production mutation blocked without trusted_mode",
        decision_hash: "mock-hash-prod-deny",
        trace: {
          policy_variant: body.policy_variant,
          tool_name: toolName,
          blast_radius_score: 80,
        },
      };
    }

    // Unknown / high-risk without allow → deny
    return {
      decision: "deny",
      deny_code: "TOOL_NOT_ALLOWED",
      deny_reason: `tool ${toolName} not allowed`,
      decision_hash: "mock-hash-deny",
      trace: { policy_variant: body.policy_variant, tool_name: toolName },
    };
  });

  return { calls };
}

afterEach(() => {
  setAuthorizeFn(null);
});

// ---------------------------------------------------------------------------
// 1. ALLOW — read-only tool in dev (via mocked SDE PDP)
// ---------------------------------------------------------------------------
describe("1. allow: read-only tool in dev", () => {
  it("allows read_file in dev environment", async () => {
    const { calls } = installScenarioPdp();
    const request: DecisionRequest = {
      tool_calls: [
        toolCall("tc-allow-1", "read_file", { path: "/tmp/notes.md" }),
      ],
      context: baseContext({ environment: "dev", trusted_mode: false }),
    };

    const response = await decide(request);
    assertContractShape(response, 1);

    const d = response.decisions[0]!;
    assert.equal(d.tool_call_id, "tc-allow-1");
    assert.equal(d.decision, "allow");
    assert.match(d.reason, /Allowed by SDE PDP/i);
    assert.equal(d.modified_arguments, null);
    assert.equal(d.evidence.proposal.tool_name, "read_file");
    assert.deepEqual(d.evidence.proposal.arguments_parsed, {
      path: "/tmp/notes.md",
    });
    assert.ok(
      d.evidence.risk_signals.some((s) => s.code === "sde_pdp_request"),
      "must record that SDE PDP path was used"
    );
    assert.equal(calls.length, 1);
    assert.equal(
      (calls[0]!.inputs.action_request as { tool_name: string }).tool_name,
      "read_file"
    );
  });
});

// ---------------------------------------------------------------------------
// 2. DENY — unknown / high-risk tool without allow rule
// ---------------------------------------------------------------------------
describe("2. deny: no allow rule (default deny)", () => {
  it("denies unknown tool in staging", async () => {
    installScenarioPdp();
    const request: DecisionRequest = {
      tool_calls: [
        toolCall("tc-deny-1", "launch_missiles", { target: "mars" }),
      ],
      context: baseContext({ environment: "staging", trusted_mode: false }),
    };

    const response = await decide(request);
    assertContractShape(response, 1);

    const d = response.decisions[0]!;
    assert.equal(d.decision, "deny");
    assert.match(d.reason, /Denied by SDE PDP/i);
    assert.ok(
      d.evidence.risk_signals.some((s) => s.code === "sde_pdp_deny_code")
    );
  });
});

// ---------------------------------------------------------------------------
// 3. PRODUCTION BLOCK — mutation tools denied in production
// ---------------------------------------------------------------------------
describe("3. production block: mutations denied without trust", () => {
  it("denies apply_patch in production when trusted_mode is false", async () => {
    const { calls } = installScenarioPdp();
    const request: DecisionRequest = {
      tool_calls: [
        toolCall("tc-prod-1", "apply_patch", {
          path: "src/app.ts",
          patch: "--- a\n+++ b\n",
        }),
      ],
      context: baseContext({
        environment: "production",
        trusted_mode: false,
        deployment_id: "dep-42",
      }),
    };

    const response = await decide(request);
    assertContractShape(response, 1);

    const d = response.decisions[0]!;
    assert.equal(d.decision, "deny");
    assert.match(d.reason, /production mutation|Denied by SDE PDP/i);
    assert.equal(calls[0]!.environment, "production");
    const action = calls[0]!.inputs.action_request as {
      deployment_id: string;
      trusted_mode: boolean;
    };
    assert.equal(action.deployment_id, "dep-42");
    assert.equal(action.trusted_mode, false);
  });

  it("denies shell with git push / rm -rf patterns in production", async () => {
    installScenarioPdp();
    const request: DecisionRequest = {
      tool_calls: [
        toolCall("tc-prod-shell", "shell", {
          command: "git push origin main && rm -rf /var/data",
        }),
      ],
      context: baseContext({
        environment: "production",
        trusted_mode: false,
      }),
    };

    const response = await decide(request);
    assertContractShape(response, 1);

    const d = response.decisions[0]!;
    assert.equal(d.decision, "deny");
    assert.match(d.reason, /Denied by SDE PDP/i);
  });
});

// ---------------------------------------------------------------------------
// 4. TRUSTED_MODE — forwarded and honored by mock PDP scenario
// ---------------------------------------------------------------------------
describe("4. trusted_mode override", () => {
  it("allows apply_patch in production when trusted_mode is true", async () => {
    const { calls } = installScenarioPdp();
    const request: DecisionRequest = {
      tool_calls: [
        toolCall("tc-trust-1", "apply_patch", {
          path: "src/app.ts",
          patch: "diff",
        }),
      ],
      context: baseContext({
        environment: "production",
        trusted_mode: true,
        deployment_id: "dep-99",
      }),
    };

    const response = await decide(request);
    assertContractShape(response, 1);

    const d = response.decisions[0]!;
    assert.equal(d.decision, "allow");
    assert.match(d.reason, /Allowed by SDE PDP/i);
    assert.ok(
      d.evidence.risk_signals.some((s) => s.code === "trusted_mode_forwarded")
    );
    assert.equal(d.passport, null);
    const action = calls[0]!.inputs.action_request as {
      trusted_mode: boolean;
      origin: { trusted_mode: boolean };
    };
    assert.equal(action.trusted_mode, true);
    assert.equal(action.origin.trusted_mode, true);
  });
});

// ---------------------------------------------------------------------------
// 5. MALFORMED INPUT — invalid top-level request and bad per-tool args
// ---------------------------------------------------------------------------
describe("5. malformed input", () => {
  it("decide() throws DecisionRequestError on missing context", async () => {
    await assert.rejects(
      () => decide({ tool_calls: [] }),
      (err: unknown) => {
        assert.ok(err instanceof DecisionRequestError);
        assert.match(err.message, /context/i);
        return true;
      }
    );
  });

  it("decideSafe() returns deny with evidence for malformed request", async () => {
    const response = await decideSafe({ not: "a valid request" });
    assertContractShape(response, 1);

    const d = response.decisions[0]!;
    assert.equal(d.decision, "deny");
    assert.match(d.reason, /malformed request/i);
    assert.ok(
      d.evidence.risk_signals.some((s) => s.code === "malformed_request")
    );
  });

  it("denies tool call with invalid JSON arguments", async () => {
    installScenarioPdp();
    const request: DecisionRequest = {
      tool_calls: [
        {
          id: "tc-bad-json",
          type: "function",
          function: {
            name: "read_file",
            arguments: "{not-valid-json",
          },
        },
      ],
      context: baseContext({ environment: "dev" }),
    };

    const response = await decide(request);
    assertContractShape(response, 1);

    const d = response.decisions[0]!;
    assert.equal(d.decision, "deny");
    assert.match(d.reason, /not valid JSON/i);
    assert.equal(d.evidence.proposal.parse_error != null, true);
  });
});

// ---------------------------------------------------------------------------
// 6. MULTI-CALL + TRACE — every tool call gets one decision; unique trace_id
// ---------------------------------------------------------------------------
describe("6. multi-call batching and trace_id", () => {
  it("emits exactly one decision per tool call with a shared trace_id", async () => {
    installScenarioPdp();
    const request: DecisionRequest = {
      tool_calls: [
        toolCall("a", "read_file", { path: "a.ts" }),
        toolCall("b", "apply_patch", { path: "b.ts" }),
        toolCall("c", "unknown_tool", {}),
      ],
      context: baseContext({ environment: "dev", trusted_mode: false }),
    };

    const response = await decide(request);
    assertContractShape(response, 3);

    assert.equal(response.decisions[0]!.tool_call_id, "a");
    assert.equal(response.decisions[0]!.decision, "allow");

    // apply_patch in dev: mock treats non-prod mutations as TOOL_NOT_ALLOWED deny
    assert.equal(response.decisions[1]!.tool_call_id, "b");
    assert.equal(response.decisions[1]!.decision, "deny");

    assert.equal(response.decisions[2]!.tool_call_id, "c");
    assert.equal(response.decisions[2]!.decision, "deny");

    const again = await decide(request);
    assert.notEqual(
      response.trace_id,
      again.trace_id,
      "each request must get a fresh trace_id"
    );
  });
});
