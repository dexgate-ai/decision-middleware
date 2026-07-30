/**
 * @dexgate/decision-middleware
 * Decision Execution Governance — core decision middleware (contract v0.1)
 *
 * Policy decisions are delegated to the SDE Enterprise PDP (HTTP /v1/authorize).
 */

export {
  decide,
  decideSafe,
  validateRequest,
  normalizeEnvironment,
  logDecisionSummary,
  DecisionRequestError,
} from "./middleware.js";

export {
  evaluatePolicy,
  setAuthorizeFn,
  loadPdpConfigFromEnv,
  SdePdpError,
  OPENCLAW_DECISION_SKU,
  CODEX_DECISION_SKU,
  DEFAULT_POLICY_VARIANT,
  SUPPORTED_DECISION_SKUS,
} from "./policy.js";

export {
  assertValidAuthorizeUrl,
  httpAuthorize,
  isRetriablePdpError,
  clampTimeoutMs,
  DEFAULT_PDP_TIMEOUT_MS,
  DEFAULT_PDP_AUTHORIZE_URL,
  MAX_PDP_ATTEMPTS,
} from "./sde-pdp-client.js";

export type {
  EvaluatePolicyOptions,
  SdePdpConfig,
  AuthorizeFn,
  SdeAuthorizeRequest,
  SdeAuthorizeResponse,
} from "./policy.js";

export {
  buildAuthorizeRequest,
  buildOpenClawActionRequest,
  buildCodexRequest,
  buildOriginMetadata,
  mapAuthorizeResponse,
  mapPdpFailure,
  normalizePdpDecision,
  pdpErrorToRiskSignalCode,
  resolvePdpSelection,
  resolveDecisionSku,
  resolvePolicyVariant,
  resolveTenantId,
  resolveGatewayId,
  isCodexSku,
  DEXGATE_ADAPTER_NAME,
  DEXGATE_ADAPTER_VERSION,
} from "./sde-pdp-adapter.js";

export { POLICY_VERSION } from "./types.js";

export type {
  ToolFunction,
  ToolCall,
  Environment,
  DecisionContext,
  DecisionRequest,
  DecisionOutcome,
  RiskSignal,
  DecisionEvidence,
  ToolDecision,
  DecisionResponse,
  PolicyEvaluation,
} from "./types.js";
