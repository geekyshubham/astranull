# Compliance and Research References

## Why references matter

AstraNull should align with authoritative guidance and provider rules, especially for high-scale simulations.

## Key public references

| Topic | Source |
|---|---|
| AWS DDoS simulation testing policy | https://aws.amazon.com/security/ddos-simulation-testing/ |
| Azure DDoS simulation testing | https://learn.microsoft.com/en-us/azure/ddos-protection/test-through-simulations |
| Cloudflare DDoS attack coverage across L3/L4/L7 | https://developers.cloudflare.com/ddos-protection/about/attack-coverage/ |
| Google Cloud Armor Adaptive Protection | https://docs.cloud.google.com/armor/docs/adaptive-protection-overview |
| GCP Packet Mirroring | https://docs.cloud.google.com/vpc/docs/packet-mirroring |
| AWS Traffic Mirroring | https://docs.aws.amazon.com/vpc/latest/mirroring/traffic-mirroring-sessions.html |
| Azure Virtual Network TAP | https://learn.microsoft.com/en-us/azure/virtual-network/virtual-network-tap-overview |
| Kubernetes DaemonSet | https://kubernetes.io/docs/concepts/workloads/controllers/daemonset/ |
| Kubernetes Sidecar Containers | https://kubernetes.io/docs/concepts/workloads/pods/sidecar-containers/ |
| OWASP API4:2023 Unrestricted Resource Consumption | https://owasp.org/API-Security/editions/2023/en/0xa4-unrestricted-resource-consumption/ |
| OWASP Denial of Service Cheat Sheet | https://cheatsheetseries.owasp.org/cheatsheets/Denial_of_Service_Cheat_Sheet.html |
| BCP 38 / RFC 2827 ingress filtering | https://www.rfc-editor.org/info/bcp38/ |
| NIST SP 800-61 Rev. 3 Incident Response Recommendations | https://csrc.nist.gov/pubs/sp/800/61/r3/final |

## Product implications from references

| Research/provider point | AstraNull implication |
|---|---|
| Cloudflare documents DDoS protection across L3/L4 and L7. | Check catalog must cover multiple layers, not only packets. |
| Google Cloud Armor Adaptive Protection focuses on L7 anomaly detection and suggested rules. | High-scale/L7 readiness needs baselines and telemetry, not just one request. |
| AWS and Azure require controlled/approved simulation approaches. | High-scale execution must be SOC-gated and authorization-driven. |
| Cloud packet mirroring exists but requires customer configuration. | Agent placement guide must explain mirror collector mode clearly. |
| Kubernetes DaemonSet runs pods on all/some nodes. | Helm agent should support DaemonSet for node-level deployment. |
| OWASP API resource consumption guidance includes rate limits and size/time limits. | API readiness checks should validate rate, size, timeout, and quota controls. |
| BCP 38 addresses spoofed-source DDoS mitigation. | AstraNull should defensively assess anti-spoofing posture where customer declares network scope, without spoofing traffic. |
| NIST incident response emphasizes preparation and response capabilities. | SOC/runbook/reporting evidence is part of readiness, not optional. |

## Compliance report mappings (SEC-009)

AstraNull report exports can be generated in framework-oriented **kinds** that attach a **compliance mapping** section. This maps **observed platform evidence** (readiness scores, test runs, verdicts, findings, high-scale authorization artifacts, SOC notes, audit log references, export custody) to **high-level control areas**. It does **not** assert that controls are satisfied and does **not** substitute for auditor or legal sign-off.

### Report templates (`src/contracts/complianceReports.mjs`)

| Kind | Audience | Primary lens |
|---|---|---|
| `executive` | Executive leadership | Governance / resilience summary |
| `board` | Board and risk committee | Risk and supplier governance |
| `technical` | Security engineering | Operational validation evidence |
| `soc` | SOC operators | High-scale and incident operations |
| `audit` | Internal/external auditors | Metadata evidence pack |
| `soc2` | Compliance and auditors | SOC 2 Trust Services Criteria buckets |
| `iso27001` | Compliance and auditors | ISO/IEC 27001 Annex A style buckets |
| `dora` | Financial-sector compliance | DORA ICT risk and resilience buckets |
| `nis2` | Essential-entity compliance | NIS2 cybersecurity measure buckets |
| `internal_audit` | Internal audit | Internal control evidence buckets |

Unknown or empty kinds normalize to `technical`.

### Evidence sources (metadata only)

Mappings reference these **evidence source labels**, not raw packets or secrets:

- `report_summary`, `readiness_score`, `test_runs`, `verdicts`, `findings`
- `high_scale_authorization_artifacts`, `soc_notes`
- `audit_log`, `export_custody`

Exports remain **redacted** and **metadata-only** per the privacy and custody models.

### Caveats

- Every mapping entry includes status text such as **requires auditor review** or **maps evidence, does not certify compliance**.
- Framework labels (SOC 2, ISO 27001, DORA, NIS2) are **orientation aids** for report packaging; customers must align control IDs with their own control matrix and engagement scope.
- **Production blockers:** formal compliance template sign-off, staging export review with customer auditors, legal review for DORA/NIS2/board packs, and immutable evidence retention (SEC-005 / SEC-008).

### Implementation touchpoints

- Pure helpers: `listReportTemplates()`, `getReportTemplate(kind)`, `buildComplianceMapping(kind)`, `normalizeReportKind(kind)`.
- `createReport()` stores a compact `summary.compliance` block (template id, frameworks, mapping count, disclaimer).
- `exportReport()` JSON includes `compliance_mapping`; markdown and HTML render a **Compliance mapping** section; custody hashes cover the full payload including mapping.

## Completion criteria

References are complete when product docs trace major design decisions to trusted public guidance and provider rules.

Compliance mappings are complete for developer validation when all report kinds above export mapping metadata with disclaimers, tests pass, and release checklist compliance gates remain open until auditor/legal/staging sign-off.
