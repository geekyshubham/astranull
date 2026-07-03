# WAF Product Catalog Seed and Version Pipeline

## Purpose

Operationalize the `waf_products` table and fingerprint catalog so detection can scale to **50+ vendor/product entries** with versioned, testable releases.

## Pipeline stages

```text
Catalog source -> validate schema -> seed migration -> runtime load -> regression tests -> version bump
```

| Stage | Owner | Output |
|---|---|---|
| Author | Detection | JSON/YAML catalog entries matching fingerprint schema. |
| Validate | Detection + Security | Schema check; no raw payloads or secrets in signatures. |
| Seed | Backend/DB | Idempotent migration or `scripts/seed-waf-products.mjs`. |
| Load | Runtime | In-memory catalog cache keyed by `fingerprint_version`. |
| Test | QA | Fixture hosts or recorded metadata responses per vendor. |
| Release | Product | Catalog version note in release notes and `PROGRESS.md`. |

## Catalog entry requirements

Each seed row must include:

| Field | Required |
|---|---|
| `vendor` | Normalized id. |
| `product` | Display name. |
| `deployment_type` | cdn, cloud_native, appliance, reverse_proxy, custom. |
| `header_name_patterns` | Safe header name regex only. |
| `cookie_name_patterns` | Safe cookie name regex only. |
| `dns_patterns` | Known edge suffixes. |
| `block_page_signature_ids` | Hash/signature ids. |
| `connector_provider_ids` | Matching connector providers. |
| `fingerprint_version` | Semver or date stamp. |
| `enabled` | Default true for seeded majors. |

## Breadth milestones

| Phase | Target count | Notes |
|---|---|---|
| R1 | 15 | Major CDN/cloud WAF families. |
| R3 | 35 | Regional appliances and secondary CDNs. |
| R5 | 50+ | Community templates + connector-mapped generics. |

## Seed artifact layout (planned)

```text
db/seeds/waf-products/
  manifest.json          # version, entry count, checksum
  vendors/
    cloudflare.json
    akamai.json
    ...
```

## Regression fixtures

| Fixture type | Use |
|---|---|
| `metadata_only_signals` | Unit tests for classifier scoring. |
| `conflicting_vendor_signals` | Confidence penalty paths. |
| `cdn_without_waf` | Separate `cdn_detected` from `waf_validated`. |

## Operator commands (planned)

```bash
npm run waf:catalog:validate   # schema + safety policy
npm run waf:catalog:seed       # dev-json or Postgres seed
npm run waf:catalog:report     # counts by vendor/deployment_type
```

## Done criteria

- Seed pipeline documented and tracked in backlog (`WAF-021`).
- Catalog version is visible in fingerprint probe evidence.
- Unknown vendor path still works with lower confidence.
- No live exploit strings in seed artifacts.