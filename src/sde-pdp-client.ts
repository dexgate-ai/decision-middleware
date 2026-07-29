/**
 * HTTP client for the SDE Enterprise Policy Decision Point (PDP).
 *
 * Source of truth: C:\dev\sde-enterprise\ops\pdp_server.py
 * Endpoint: POST /v1/authorize
 *
 * Defaults:
 * - total time budget 4000ms (override with SDE_PDP_TIMEOUT_MS)
 * - authorize URL http://127.0.0.1:8001/v1/authorize
 * - at most 1 retry on network error or HTTP 5xx (not on 4xx / timeout / parse errors)
 *
 * Fail-closed: all transport / HTTP / parse failures throw SdePdpError;
 * policy layer maps those to decision=deny with typed risk_signals.
 */

export const OPENCLAW_DECISION_SKU = "openclaw.trusted_mode.authorize.v1";
export const CODEX_DECISION_SKU = "codex.trusted_mode.authorize.v1";

/** SKUs currently accepted by SDE PDP /v1/authorize. */
export const SUPPORTED_DECISION_SKUS = [
  OPENCLAW_DECISION_SKU,
  CODEX_DECISION_SKU,
] as const;

export type SupportedDecisionSku = (typeof SUPPORTED_DECISION_SKUS)[number];

/** Default total authorize time budget (ms). */
export const DEFAULT_PDP_TIMEOUT_MS = 4000;

/** Max attempts = 1 initial + at most 1 retry. */
export const MAX_PDP_ATTEMPTS = 2;

export const DEFAULT_PDP_AUTHORIZE_URL =
  "http://127.0.0.1:8001/v1/authorize";

/** Default policy pack variant used when none is selected. */
export const DEFAULT_POLICY_VARIANT = "guard-pro.v2026.02";

/** Request body accepted by SDE PDP POST /v1/authorize. */
export interface SdeAuthorizeRequest {
  decision_sku: string;
  policy_variant: string;
  inputs: {
    action_request?: Record<string, unknown>;
    request?: Record<string, unknown>;
    environment?: string;
    gateway_id?: string;
    [key: string]: unknown;
  };
  tenant_id?: string | null;
  gateway_id?: string | null;
  environment?: string | null;
}

/** Subset of the PDP authorize response we map from. */
export interface SdeAuthorizeResponse {
  decision?: string;
  deny_code?: string | null;
  deny_reason?: string | null;
  constraints?: unknown;
  decision_hash?: string;
  decision_proof?: unknown;
  passport?: unknown;
  trace?: Record<string, unknown>;
  enforcement_mode?: string;
  enforcement_bypassed?: boolean;
  would_have_decision?: string;
  would_have_deny_code?: string;
  [key: string]: unknown;
}

export interface SdePdpConfig {
  authorizeUrl: string;
  tenantId: string;
  policyVariant: string;
  decisionSku: string;
  authToken?: string;
  /** Total time budget for authorize (includes any retry). Default 4000. */
  timeoutMs: number;
  gatewayId?: string;
}

export type AuthorizeFn = (
  body: SdeAuthorizeRequest,
  config: SdePdpConfig
) => Promise<SdeAuthorizeResponse>;

export class SdePdpError extends Error {
  readonly code: string;
  readonly status?: number;
  readonly causeDetail?: unknown;
  readonly latencyMs?: number;
  readonly attempts?: number;

  constructor(
    message: string,
    code: string,
    opts?: {
      status?: number;
      causeDetail?: unknown;
      latencyMs?: number;
      attempts?: number;
    }
  ) {
    super(message);
    this.name = "SdePdpError";
    this.code = code;
    this.status = opts?.status;
    this.causeDetail = opts?.causeDetail;
    this.latencyMs = opts?.latencyMs;
    this.attempts = opts?.attempts;
  }
}

/**
 * Validate authorize URL. Throws SdePdpError with PDP_URL_MISSING / PDP_URL_INVALID.
 */
export function assertValidAuthorizeUrl(url: string | undefined | null): string {
  const trimmed = typeof url === "string" ? url.trim() : "";
  if (!trimmed) {
    throw new SdePdpError(
      "SDE_PDP_URL is missing or empty. Set SDE_PDP_URL to the PDP authorize endpoint " +
        `(e.g. ${DEFAULT_PDP_AUTHORIZE_URL}).`,
      "PDP_URL_MISSING"
    );
  }

  let parsed: URL;
  try {
    parsed = new URL(trimmed);
  } catch {
    throw new SdePdpError(
      `SDE_PDP_URL is not a valid absolute URL: "${trimmed}". ` +
        `Example: ${DEFAULT_PDP_AUTHORIZE_URL}`,
      "PDP_URL_INVALID"
    );
  }

  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
    throw new SdePdpError(
      `SDE_PDP_URL must use http or https (got ${parsed.protocol}).`,
      "PDP_URL_INVALID"
    );
  }

  return trimmed;
}

export function clampTimeoutMs(raw: number): number {
  if (!Number.isFinite(raw) || raw <= 0) return DEFAULT_PDP_TIMEOUT_MS;
  // Keep timeouts in a sensible band for live authorize calls.
  return Math.min(Math.max(Math.floor(raw), 500), 60_000);
}

export function loadPdpConfigFromEnv(
  env: NodeJS.ProcessEnv = process.env
): SdePdpConfig {
  const timeoutRaw =
    env.SDE_PDP_TIMEOUT_MS ??
    env.PDP_TIMEOUT_MS ??
    String(DEFAULT_PDP_TIMEOUT_MS);
  const timeoutMs = clampTimeoutMs(Number.parseInt(timeoutRaw, 10));
  const authToken =
    env.SDE_PDP_AUTH_TOKEN?.trim() ||
    env.PDP_AUTH_TOKEN?.trim() ||
    undefined;

  const rawUrl =
    env.SDE_PDP_URL?.trim() ||
    env.PDP_URL?.trim() ||
    DEFAULT_PDP_AUTHORIZE_URL;

  const decisionSku =
    env.SDE_PDP_SKU?.trim() ||
    env.SDE_PDP_DECISION_SKU?.trim() ||
    OPENCLAW_DECISION_SKU;

  const policyVariant =
    env.SDE_PDP_POLICY_VARIANT?.trim() ||
    env.POLICY_VARIANT?.trim() ||
    DEFAULT_POLICY_VARIANT;

  return {
    authorizeUrl: rawUrl,
    tenantId:
      env.SDE_PDP_TENANT_ID?.trim() ||
      env.TENANT_ID?.trim() ||
      "trial-tenant",
    policyVariant,
    decisionSku,
    authToken: authToken || undefined,
    timeoutMs,
    gatewayId:
      env.SDE_PDP_GATEWAY_ID?.trim() ||
      env.ASSESS_GATEWAY_ID?.trim() ||
      undefined,
  };
}

function logLivePdpCall(fields: {
  sku: string;
  decision: string;
  latencyMs: number;
  urlHost: string;
  attempts: number;
  errorCode?: string;
  retried?: boolean;
}): void {
  // Compact stdout line — no request/response payloads.
  const retry = fields.retried ? " retried=1" : "";
  const base =
    `sde_pdp authorize sku=${fields.sku} decision=${fields.decision} ` +
    `latency_ms=${fields.latencyMs} attempts=${fields.attempts} host=${fields.urlHost}${retry}`;
  if (fields.errorCode) {
    console.log(`${base} error=${fields.errorCode}`);
  } else {
    console.log(base);
  }
}

function hostOf(url: string): string {
  try {
    return new URL(url).host;
  } catch {
    return "invalid-url";
  }
}

function isAbortError(err: unknown): boolean {
  if (err == null || typeof err !== "object") return false;
  const name = (err as { name?: string }).name;
  return name === "AbortError" || name === "TimeoutError";
}

/**
 * Whether an error is eligible for a single retry.
 * - network / transport → yes
 * - HTTP 5xx → yes
 * - HTTP 4xx, auth, timeout, invalid body, URL issues → no
 * - Successful 2xx with decision deny is not an error (no retry path)
 */
export function isRetriablePdpError(err: SdePdpError): boolean {
  if (err.code === "PDP_TRANSPORT_ERROR") return true;
  if (err.code === "PDP_HTTP_ERROR" && err.status != null && err.status >= 500) {
    return true;
  }
  return false;
}

interface AttemptResult {
  response: SdeAuthorizeResponse;
  latencyMs: number;
}

/**
 * Single HTTP attempt. `attemptTimeoutMs` is the remaining budget for this try.
 */
async function authorizeAttempt(opts: {
  body: SdeAuthorizeRequest;
  authorizeUrl: string;
  headers: Record<string, string>;
  attemptTimeoutMs: number;
  sku: string;
}): Promise<AttemptResult> {
  const { body, authorizeUrl, headers, attemptTimeoutMs, sku } = opts;
  const started = Date.now();
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), attemptTimeoutMs);

  try {
    let res: Response;
    try {
      res = await fetch(authorizeUrl, {
        method: "POST",
        headers,
        body: JSON.stringify(body),
        signal: controller.signal,
      });
    } catch (err) {
      const latencyMs = Date.now() - started;
      if (isAbortError(err)) {
        throw new SdePdpError(
          `SDE PDP authorize timed out after ${attemptTimeoutMs}ms ` +
            `(url=${authorizeUrl}). Fail closed.`,
          "PDP_TIMEOUT",
          { latencyMs }
        );
      }
      const message = err instanceof Error ? err.message : String(err);
      throw new SdePdpError(
        `SDE PDP unreachable at ${authorizeUrl}: ${message}. ` +
          `Check that the PDP is running and SDE_PDP_URL is correct. Fail closed.`,
        "PDP_TRANSPORT_ERROR",
        { causeDetail: err, latencyMs }
      );
    }

    const text = await res.text();
    const latencyMs = Date.now() - started;

    let parsed: unknown;
    try {
      parsed = text ? JSON.parse(text) : {};
    } catch {
      throw new SdePdpError(
        `SDE PDP returned non-JSON body (HTTP ${res.status}) from ${authorizeUrl}. Fail closed.`,
        "PDP_INVALID_RESPONSE",
        { status: res.status, causeDetail: text.slice(0, 200), latencyMs }
      );
    }

    if (!res.ok) {
      const detail =
        typeof parsed === "object" &&
        parsed !== null &&
        "detail" in parsed
          ? String((parsed as { detail: unknown }).detail)
          : text.slice(0, 200);

      // 4xx auth vs other client/server errors — 5xx retriable at outer layer.
      if (res.status === 401 || res.status === 403) {
        throw new SdePdpError(
          `SDE PDP authorize failed with HTTP ${res.status} at ${authorizeUrl}: ${detail}. Fail closed.`,
          "PDP_AUTH_FAILED",
          { status: res.status, causeDetail: parsed, latencyMs }
        );
      }

      throw new SdePdpError(
        `SDE PDP authorize failed with HTTP ${res.status} at ${authorizeUrl}: ${detail}. Fail closed.`,
        "PDP_HTTP_ERROR",
        { status: res.status, causeDetail: parsed, latencyMs }
      );
    }

    if (parsed == null || typeof parsed !== "object") {
      throw new SdePdpError(
        `SDE PDP returned an empty or non-object response from ${authorizeUrl}. Fail closed.`,
        "PDP_INVALID_RESPONSE",
        { status: res.status, latencyMs }
      );
    }

    // Successful 2xx — including decision=deny. Caller does not retry.
    void sku;
    return {
      response: parsed as SdeAuthorizeResponse,
      latencyMs,
    };
  } finally {
    clearTimeout(timer);
  }
}

/**
 * Default transport: HTTP POST to SDE PDP /v1/authorize.
 *
 * - Total wall-clock budget = config.timeoutMs (default 4000).
 * - At most 1 retry on network error or HTTP 5xx.
 * - No retry on 4xx, auth failure, timeout, or unparseable body.
 * - Each attempt is capped by remaining budget.
 * - Logs SKU, decision, latency_ms, attempts (no full payloads).
 */
export async function httpAuthorize(
  body: SdeAuthorizeRequest,
  config: SdePdpConfig
): Promise<SdeAuthorizeResponse> {
  const authorizeUrl = assertValidAuthorizeUrl(config.authorizeUrl);
  const budgetMs = clampTimeoutMs(config.timeoutMs);
  const sku = body.decision_sku || config.decisionSku || "unknown";
  const budgetStarted = Date.now();

  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    Accept: "application/json",
  };
  if (config.authToken) {
    headers.Authorization = `Bearer ${config.authToken}`;
  }

  let lastError: SdePdpError | null = null;
  let attempts = 0;

  for (let attempt = 1; attempt <= MAX_PDP_ATTEMPTS; attempt++) {
    const elapsed = Date.now() - budgetStarted;
    const remaining = budgetMs - elapsed;

    if (remaining <= 0) {
      lastError = new SdePdpError(
        `SDE PDP authorize exhausted ${budgetMs}ms total budget ` +
          `(url=${authorizeUrl}). Fail closed.`,
        "PDP_TIMEOUT",
        { latencyMs: elapsed, attempts }
      );
      break;
    }

    attempts = attempt;

    try {
      const result = await authorizeAttempt({
        body,
        authorizeUrl,
        headers,
        attemptTimeoutMs: remaining,
        sku,
      });

      const totalLatency = Date.now() - budgetStarted;
      const decision =
        typeof result.response.decision === "string" && result.response.decision
          ? result.response.decision
          : "unknown";

      logLivePdpCall({
        sku,
        decision,
        latencyMs: totalLatency,
        urlHost: hostOf(authorizeUrl),
        attempts,
        retried: attempts > 1,
      });

      return result.response;
    } catch (err) {
      const pdpErr =
        err instanceof SdePdpError
          ? err
          : new SdePdpError(
              `SDE PDP authorize unexpected error: ${String(err)}. Fail closed.`,
              "PDP_TRANSPORT_ERROR",
              {
                causeDetail: err,
                latencyMs: Date.now() - budgetStarted,
                attempts,
              }
            );

      lastError = new SdePdpError(pdpErr.message, pdpErr.code, {
        status: pdpErr.status,
        causeDetail: pdpErr.causeDetail,
        latencyMs: Date.now() - budgetStarted,
        attempts,
      });

      const canRetry =
        attempt < MAX_PDP_ATTEMPTS && isRetriablePdpError(pdpErr);
      const remainingAfter = budgetMs - (Date.now() - budgetStarted);

      if (!canRetry || remainingAfter <= 0) {
        break;
      }

      // Retry immediately with remaining budget (no artificial delay).
      console.log(
        `sde_pdp authorize retry sku=${sku} after=${pdpErr.code} ` +
          `attempt=${attempt} remaining_ms=${remainingAfter} host=${hostOf(authorizeUrl)}`
      );
    }
  }

  const finalError =
    lastError ??
    new SdePdpError(
      `SDE PDP authorize failed with no result after ${attempts} attempt(s). Fail closed.`,
      "PDP_TRANSPORT_ERROR",
      { latencyMs: Date.now() - budgetStarted, attempts }
    );

  logLivePdpCall({
    sku,
    decision: "error",
    latencyMs: finalError.latencyMs ?? Date.now() - budgetStarted,
    urlHost: hostOf(authorizeUrl),
    attempts: finalError.attempts ?? attempts,
    errorCode: finalError.code,
    retried: (finalError.attempts ?? attempts) > 1,
  });

  throw finalError;
}

let authorizeImpl: AuthorizeFn = httpAuthorize;

/** Inject a mock authorize function (tests). Pass null to restore HTTP default. */
export function setAuthorizeFn(fn: AuthorizeFn | null): void {
  authorizeImpl = fn ?? httpAuthorize;
}

export function getAuthorizeFn(): AuthorizeFn {
  return authorizeImpl;
}

export async function authorizeWithPdp(
  body: SdeAuthorizeRequest,
  config?: SdePdpConfig
): Promise<SdeAuthorizeResponse> {
  const resolved = config ?? loadPdpConfigFromEnv();
  // Validate early so mocks that ignore URL still allow unit tests;
  // live httpAuthorize also re-validates.
  if (authorizeImpl === httpAuthorize) {
    assertValidAuthorizeUrl(resolved.authorizeUrl);
  }
  return authorizeImpl(body, resolved);
}
