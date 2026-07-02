# ADR-0004: Target Groups as Core Scope Boundary

## Status

Accepted.

## Context

Without inventory discovery, the product needs a clean unit of scope, ownership, readiness score, and reporting.

## Decision

AstraNull uses target groups as the primary product object. Every run, finding, report, agent binding, expected behavior, and high-scale request links to a target group.

## Consequences

| Positive | Negative |
|---|---|
| Simple mental model. | Requires customers to group targets correctly. |
| Enables business-service scoring. | Misgrouping can affect score relevance. |
| Works across cloud/on-prem. | Needs good import and edit UX. |
