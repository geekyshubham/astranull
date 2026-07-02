# ADR-0001: No IP Inventory Discovery in Core Product

## Status

Accepted.

## Context

The product is intended to work without customer cloud credentials and without broad inventory scanning. The user explicitly requested dropping IP inventory discovery.

## Decision

AstraNull core product will use customer-declared target groups. Targets can be entered manually or imported via CSV/API. Optional enhanced connectors may be added later, but no core feature depends on automatic IP discovery.

## Consequences

| Positive | Negative |
|---|---|
| Lower trust barrier. | Customer must provide accurate scope. |
| Easier enterprise approval. | Coverage is limited to declared targets. |
| Less noisy and safer. | Cannot claim full enterprise exposure map. |

## UX requirement

The UI must clearly say: “AstraNull validates the targets you declare.”
