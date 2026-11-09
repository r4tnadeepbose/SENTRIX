# SENTRIX research synthesis

Research completed against the official OASM and OWASP DefectDojo repositories on 8 November 2026. This document records product-pattern research only; SENTRIX does not copy either project's source, visual assets, branding, or data model.

## Reference findings

| Area | Reference | Verified pattern | SENTRIX direction |
| --- | --- | --- | --- |
| Attack-surface management | OASM | Asset inventory, groups, scheduled workflows, connector-based scans and worker status | Detection-derived inventory now exists; connector/worker execution remains a future integration boundary. |
| Asset inventory | OASM | Domains, IPs, services, technologies, URLs and certificates with filters and topology | Extend only from authoritative SENTRIX sources; never invent relationships. |
| Scanning operations | OASM | Queued workflows delegated to isolated workers | Keep SENTRIX's bounded local jobs; report an external scanner only after installation and execution are verified. |
| AI Studio | OASM | Ask/agent modes, explicit approvals, tool activity and worker isolation | Keep masked, read-only assisted triage as the present capability; all side effects require a separate approval boundary. |
| Finding lifecycle | DefectDojo | Findings, deduplication, remediation and reporting in a governed workflow | Preserve SENTRIX fingerprints, evidence provenance, status history, risk scoring and audit events. |
| Risk governance | DefectDojo | Risk acceptance and expiry-based review | Use explicit owner, reason, expiry and auditable status transitions. |
| Reporting | DefectDojo | Metrics and scanner-result ingestion | Generate reporting from persisted SENTRIX records, not fabricated operational data. |

## Capability classification

| Capability | Classification | Notes |
| --- | --- | --- |
| Secret exposure detection, masked evidence, explainable risk and finding history | Already implemented | Verified in SENTRIX detector, pipeline and storage modules. |
| Detection-derived asset inventory and coverage | Implemented but incomplete | It reflects recorded findings, not a cloud-authoritative CMDB. |
| Scheduled local scan jobs | Already implemented | Local worker-pool jobs are present; distributed workers are not claimed. |
| Finding lifecycle, deduplication, remediation and reports | Already implemented | Existing records remain the system of record. |
| Risk acceptance | Implemented but incomplete | Explicit persisted acceptance records are being added; approval workflow is still a future increment. |
| Hubs channels, DMs, notifications and pings | Implemented but incomplete | Persistent SQLite messages, channel authorization, DMs, recipient notifications, presence and unlimited person-to-person pings are implemented. Attachment handling, desktop notifications and administrative membership management remain future work. |
| OASM-style external worker fleet, container connectors and browser agents | Not appropriate yet | They require an explicit deployment and isolation design beyond the standard-library modular monolith. |

## License boundary

OASM is GPL-3.0 and DefectDojo is BSD-3-Clause. SENTRIX uses product-level inspiration and independently written code only; neither reference project's code or branded visual assets are incorporated.

## Sources

- [OASM repository README](https://github.com/oasm-platform/open-asm/blob/main/README.md)
- [OASM GPL-3.0 license](https://github.com/oasm-platform/open-asm/blob/main/LICENSE)
- [DefectDojo repository README](https://github.com/DefectDojo/django-DefectDojo/blob/master/README.md)
- [DefectDojo BSD-3-Clause license](https://github.com/DefectDojo/django-DefectDojo/blob/master/LICENSE.md)
