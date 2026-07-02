# Protocol Vectors: HTTP/2, HTTP/3, QUIC, WebSocket

## Purpose

Modern protocols can change DDoS behavior. AstraNull should validate whether they are intentionally exposed and protected.

## Vectors

| Protocol | Vector class | Safe validation | SOC-gated validation |
|---|---|---|---|
| HTTP/2 | Stream/reset abuse class | Check if HTTP/2 enabled and safe limits expected | High-scale only with SOC. |
| HTTP/3/QUIC | UDP/443 request volume class | Check if enabled and declared | High-scale only with SOC. |
| WebSocket | Long-lived connection class | Low-count connection/timeout check | High-scale only with SOC. |
| SSE | Long-lived stream class | Low-count timeout check | High-scale only with SOC. |
| gRPC | HTTP/2 request/stream class | Safe method/timeout/limit check | High-scale only with SOC. |

## Safe validation examples

- protocol enabled/disabled check,
- response behavior check,
- timeout/idle behavior check,
- low-count connection limit check,
- canary request with nonce.

## Completion criteria

Protocol readiness is complete when AstraNull can show which protocols are exposed, whether safe limits are configured, and whether high-scale testing requires SOC approval.
