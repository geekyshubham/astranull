# ADR-0003: SOC-Gated High-Scale DDoS Validation

## Status

Accepted.

## Context

High-scale DDoS validation can be disruptive and may require cloud/CDN/provider approval. Customers should not be able to launch such tests directly.

## Decision

High-scale tests are request-only for customers and executable only by AstraNull SOC after authorization gates pass.

## Consequences

| Positive | Negative |
|---|---|
| Reduces abuse and legal risk. | More operational work for SOC. |
| Aligns with provider approval models. | Slower than self-service. |
| Enterprise-friendly governance. | Requires strong workflow tooling. |

## Implementation requirement

Customer-facing APIs must not expose high-scale start/stop execution. Only internal SOC APIs can call execution adapters.
