# TLS and Connection Vectors

## Readiness questions

- Are TLS handshake and connection limits configured?
- Are idle/slow connections timed out?
- Are oversized headers/body rejected safely?
- Are modern protocols intentionally enabled and protected?

## Vector table

| Vector | Safe validation | High-scale validation | Signals |
|---|---|---|---|
| TLS handshake exhaustion class | Single/few handshake checks and config expectations | SOC-approved only | Handshake latency, errors, CPU/load. |
| Slow headers/body class | Very small controlled timeout check | SOC-approved only | Timeout behavior, connection count. |
| Connection hoarding | Low-count connection limit check | SOC-approved only | Active connections, app health. |
| Idle timeout missing | Safe timeout observation | Not usually high-scale | Connection close timing. |
| Header/body size limits | Bounded request size checks | SOC-approved if needed | Rejection code, logs. |

## Safe limits

The product must never run large connection exhaustion tests outside SOC approval. Safe checks should use minimal counts and focus on configuration behavior.

## Completion criteria

TLS/connection validation is complete when it identifies missing timeout/limit controls without becoming a load generator.
