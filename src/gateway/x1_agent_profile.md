# X1 Agent Profile

X1 talks to LayerX1 with the **standard OpenAI Responses** request JSON and SSE `data:` stream. The X1 Agent Profile is a harness-only, versioned, namespaced, opt-in overlay: extra HTTP headers on inference requests, plus a decoder contract for future `x1.*` stream events. It does not introduce a new transport and it does not add a top-level `x1` field to the Responses body.

No LayerX1 server changes were made. Until the server acknowledges the profile, behavior **degrades to pure Responses**.

## Wire shape

Inference POST `/v1/responses` keeps the usual Responses fields (`model`, `stream`, `instructions`, `input`, `tools`, `tool_choice`, `parallel_tool_calls`, `include`, `text`, optional `reasoning` / `max_output_tokens`). Profile data lives only in headers:

| Header | Value |
| --- | --- |
| `x-layerx1-agent-protocol` | `1` |
| `x-layerx1-client` | `x1/<app-version>` |
| `x-layerx1-client-capabilities` | deterministic, bounded list: `encrypted-reasoning-state,parallel-tool-calls,responses-sse` |
| `idempotency-key` | omitted today |

`responses-sse` is required; the others are optional. Negotiation fails closed only when the server actually returns a capability acknowledgement that omits a required feature. No acknowledgement is the current production path and must not fail.

Native HTTP, WASM host, and N-API host transports send the same profile headers. Account and model-catalog GETs do not.

## Idempotency (not sent)

`RequestIdentity.idempotency_key` is typed and validated, but `identityForRequest` always returns `null`. `ModelRequest` currently exposes `session_id` (session-scoped) and `trace_ctx.turn_id` (process-local telemetry). Those are not a stable per-turn identity. Future wiring: add a durable per-turn field on `ModelRequest` owned by the agent runtime, then return it from `src/gateway/x1_agent_profile.zig` `identityForRequest`. Do not synthesize a key from model, prompt, session id, or the telemetry turn counter.

## Stream events

The Responses reducer still owns `response.*` events. `x1.*` events are parsed only when the JSON `type` is explicitly namespaced and valid. Unknown or malformed `x1.*` events are ignored and do not break an ordinary Responses stream. Recognized future events (`x1.capability.ack`, `x1.reasoning.delta`, `x1.usage`) map into existing harness events only when a truthful variant already exists. Hidden chain-of-thought, routing, billing, and cache facts are not invented from these events.

## Compatibility

- **OpenAI clients** remain valid: they send standard Responses JSON and may omit X1 headers. Spec-compliant Responses endpoints ignore unknown headers.
- **Anthropic adapters** are unchanged. This profile is not an Anthropic Messages wire and is not injected into non-Responses adapters.
- **Model-neutral internal adapters** still consume `stream_provider.Event` from the Responses reducer. Optional X1 headers and ignored `x1.*` events do not change that contract.

Owned by `src/gateway/x1_agent_profile.zig`.
