# CrimeGPT production readiness and approval register

This register separates implemented controls from activities that require Karnataka Police/SCRB authority. A datathon deployment must not be represented as an operational police system until every external gate is signed.

## Implemented engineering controls

| Area | Control | Verification |
|---|---|---|
| Data ingestion | UTF-8 CSV/JSON CCTNS mapping, required-field checks, SHA-256 duplicate detection, rejected-row report and immutable import audit | `POST /api/admin/import-cctns` as analyst/supervisor |
| Live records | Cloud deployments default to **no demo seeding**. Demo data requires explicit `SEED_DEMO_DATA=1` | Start AppSail with `SEED_DEMO_DATA=0` |
| Cloud persistence | FIRs, conversations, extractions and optional audit events mirror to Catalyst Data Store; source files use Catalyst File Store | `/ready` and Catalyst console |
| Model governance | Explainable baseline records version, features and contributions; evaluation refuses to claim validation without confirmed labels | `GET /api/model/evaluation` |
| Multilingual intelligence | Unicode FIR intake, English/Kannada language detection, evidence-constrained model contract and deterministic fallback | Automated Kannada question test |
| Voice | Browser speech recognition and synthesis use `en-IN` and `kn-IN`; unsupported browsers fail closed with a visible disabled control | Chrome/Safari device acceptance test |
| PDF | Conversation, evidence, confidence and warning export as a real PDF | Automated `%PDF` and size test |
| Access control | Server-side investigator, analyst, supervisor and policymaker permissions; Catalyst identity is authoritative in cloud | `GET /api/admin/permissions` |
| Security | CSRF, secure cookies, 30-minute sessions, CSP, clickjacking/MIME/referrer controls, upload limits and evidence-only answers | Automated security tests |
| Audit and monitoring | Access/query/import/export/retention audit, readiness check, route latency/error counts and `Server-Timing` | `/ready`, supervisor `/api/metrics`, `/api/audit` |
| Backup and retention | Consistent supervisor-only database snapshot and audited conversation retention action | `/api/admin/backup`, `POST /api/admin/retention` |

## Required Catalyst production settings

Set these in the production environment, not in Git:

```text
SECRET_KEY=<random 32+ byte secret from approved secret manager>
COOKIE_SECURE=1
CATALYST_CLOUD_ENABLED=1
CATALYST_AUTH_ENABLED=1
SEED_DEMO_DATA=0
SYNC_AUDIT_TO_CLOUD=1
DOCUMENT_FOLDER_REF=<approved encrypted File Store folder>
AI_ENDPOINT_URL=<private approved model gateway>
AI_API_KEY=<secret manager reference>
```

Use separate Development, Staging and Production Catalyst projects. Restrict production deploy rights, enable alerting for `/ready` failures and 5xx rate, and export backups to an approved encrypted KSP vault. The downloadable SQLite snapshot is an emergency/application-level export, not the only backup mechanism.

## Load-test acceptance profile

Test only Staging with anonymised synthetic records. Model the 1,100 stations as concurrent tenants:

- 1,100 authenticated virtual users ramped over 10 minutes.
- 70% case search/list, 15% case board, 10% grounded query, 4% dashboard, 1% controlled FIR intake.
- Run 30 minutes steady state and a 10-minute two-times spike.
- Targets: p95 read latency below 2 seconds, p95 grounded-query latency below 8 seconds, error rate below 1%, no cross-role or cross-unit leakage, and no lost accepted FIR.
- Capture AppSail CPU/memory/restarts, Catalyst Data Store throttles, model latency, queue depth and `/api/metrics` route data.

Do not run this profile against the public development deployment. A production result requires a dedicated load generator, staging capacity and written SCRB approval.

## Model validation protocol

The current score is an explainable baseline, not a trained or validated prediction model. A valid model requires an SCRB-approved, de-identified and temporally split dataset with a clearly defined outcome. Minimum review:

1. Freeze the outcome definition and leakage-safe feature list before training.
2. Split by time and district; never randomly split records belonging to the same person/case network.
3. Compare against a simple baseline and report precision, recall, false-positive rate, calibration and district/language/subgroup slices.
4. Perform investigator blind review of false positives and false negatives.
5. Set an operating threshold based on investigative capacity and documented harm analysis.
6. Register model owner, version, training-data period, limitations, rollback version and review date.
7. Keep scores advisory; never automate arrest, surveillance or adverse action.

Confirmed outcomes can be attached to `model_predictions.outcome`; `/api/model/evaluation` then reports threshold metrics. Training should occur in an approved isolated ML environment, not inside the public web process.

## External approval gates — not achievable by source code alone

| Gate | Required owner/evidence | Status |
|---|---|---|
| SCRB/CCTNS live-data access | SCRB data owner; schema/data-sharing approval and service credentials | Awaiting authority |
| Data mapping acceptance | CCTNS domain owner; signed field mapping and reconciliation sample | Awaiting authority |
| Model validation | SCRB analytics lead + independent reviewer; signed validation report | Awaiting labelled data |
| DPIA/privacy review | Department legal/privacy officer; purpose, minimisation, retention and data-subject controls | Awaiting authority |
| Security assessment | CERT-In empanelled/department-approved assessor; VAPT report and remediation closure | Awaiting commissioned test |
| Voice/language acceptance | Kannada-speaking investigators; device/browser accuracy report | Awaiting user acceptance test |
| Disaster recovery exercise | SCRB IT owner; successful restore with agreed RPO/RTO | Awaiting staging infrastructure |
| Operational go-live | Authorised department change board; owner, support roster and rollback approval | Not approved |

Until those rows are signed, label the product **Datathon / controlled pilot — no live personal data**.
