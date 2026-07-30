# Changelog

## 0.1.1

- Emit one compact JSON `decision_summary` line per tool decision (`tool`, `decision`, `deny_code`, `latency_ms`, `trace_id`, `policy_variant`). No arguments, tokens, or full evidence.
- Normalize `context.environment` aliases: `prod`/`prd` → `production`, `stage`/`stg`/`qa` → `staging`, `development`/`local` → `dev`.
- Document environment vocabulary and decision_summary logging in the README.
- **No breaking changes** to the DecisionRequest / DecisionResponse contract or HTTP API.

## 0.1.0

- Initial public release: library `decide` / `decideSafe`, HTTP `/v1/decide` + `/v1/decide-safe` + `/health`.
- SDE PDP authorize client with timeout/retry and fail-closed mapping.
- Optional per-request `tenant_id` / `gateway_id` and SKU selection.
