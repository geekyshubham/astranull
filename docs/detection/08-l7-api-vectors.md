# L7 and API Vectors

## Scope

Layer 7 readiness includes HTTP, HTTPS, APIs, WAF behavior, rate limits, bot controls, cache behavior, and expensive endpoint protection.

## Vector table

| Vector | Safe validation | SOC/high-scale validation | Detection signals |
|---|---|---|---|
| HTTP GET/POST flood class | Low-rate canary and rate-limit checks | SOC-approved sustained request simulation | Response code, latency, origin RPS, agent/log observations. |
| Cache-busting class | Safe variant request sample | SOC-approved L7 scenario | Cache hit/miss if available, origin observations. |
| Expensive endpoint abuse | Customer-declared low-rate check | SOC-approved scenario with clear limits | CPU/latency/error rates, logs, rate-limit responses. |
| Login/OTP/auth abuse | Safe test endpoint or marker only | SOC-approved if customer approves | Rate-limit/challenge evidence, no real user impact. |
| Upload/export/report abuse | Size/limit metadata check | SOC-approved with dummy endpoints only | Request rejection/limit evidence. |
| GraphQL deep/nested query class | Safe customer-provided marker query | SOC-approved only | Execution limits, response behavior. |
| Batch API abuse | Low-count batch-limit check | SOC-approved only | Limit response, latency. |
| WAF marker rule | Benign marker header/path | Not high-scale | WAF block/challenge + agent not observed. |
| HTTP method abuse | TRACE/unusual methods safe check | Not high-scale | Response code, agent/log observation. |
| Oversized headers/body | Strictly bounded size checks | SOC-approved if scale | Rejection/timeout behavior. |
| WebSocket/SSE connection hoarding | Low-count timeout check | SOC-approved scale | Connection limits, server health. |

## WAF marker rule pattern

Customer creates a harmless WAF rule that matches a unique AstraNull marker such as a custom header or path. AstraNull sends a single request with that marker and verifies:

- external response indicates block/challenge as expected,
- agent did not observe traffic if block-before-origin is expected,
- logs/evidence show rule behavior if integrated.

## Rate-limit validation

Rate-limit checks must be bounded.

Fields:

| Field | Description |
|---|---|
| safe_threshold | Customer-declared low threshold for test endpoint. |
| max_requests | Hard cap enforced by backend. |
| interval | Time window. |
| expected_action | Block, challenge, throttle, 429, custom. |
| stop_on_first_limit | Default true. |

## API resource exhaustion readiness

Check for customer-declared controls:

- request rate limit,
- body size limit,
- upload size limit,
- query depth/complexity limit,
- pagination/max results,
- timeout,
- concurrency cap,
- authentication cost controls,
- per-user/API-key/org quotas.

## Completion criteria

L7/API validation is complete when safe tests prove expected WAF/rate/API behavior and high-scale L7 scenarios are only available through SOC-gated workflow.
