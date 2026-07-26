# CrimeGPT - KSP Crime Intelligence Platform

CrimeGPT is a Flask-based crime intelligence prototype for Datathon 2026 Problem Statement 1. It provides FIR intake, role-aware case access, relationship graphs, evidence-grounded queries, hotspot signals, and interactive investigation storylines.

## Features

- Catalyst Data Store-backed FIR, conversation, extraction, and audit persistence with a local SQLite query cache
- Catalyst Hosted Authentication with role-aware navigation in AppSail; hashed demo accounts remain local-only
- Multilingual FIR narrative intake through manual entry, PDF, or TXT upload
- Searchable case workspace and aggregate intelligence dashboard
- Interactive, draggable and zoomable investigation graphs
- Full-screen graph exploration and focused connection views
- Data-driven hotspot and repeat-offender colours
- Animated incident, offender, and hotspot storylines
- Record-level evidence trails and persistent audit events
- Catalyst QuickML LLM Serving analytics with evidence-ID validation
- QuickML RAG grounding with role-filtered manual retrieval fallback when RAG is unavailable
- English and Kannada voice input/output controls

## Local setup

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install Flask pypdf
python app.py
```

Open [http://127.0.0.1:5000](http://127.0.0.1:5000).

Demo investigator credentials:

```text
Officer ID: INV001
Password: demo123
```

The local SQLite database is generated automatically and is excluded from Git. Replace the development secret and demo authentication before deployment.

## Catalyst production configuration

AppSail initializes the Catalyst Python SDK per request. Set `CATALYST_CLOUD_ENABLED=1` to require Data Store persistence. The application uses `CaseMaster`, `Conversations`, `AuditEvents`, and `FIRExtractions`, each with `ExternalID` and `Payload` columns.

The development project is configured with the `CrimeGPT_FIR_Documents` File Store folder. Override its numeric ID through `DOCUMENT_FOLDER_REF` when deploying this code to another Catalyst project. Without a valid folder, extracted FIR records remain persistent but the original uploaded binary is not copied into File Store.

### Catalyst QuickML Generative AI setup

No OpenAI, Anthropic, or other external model API is used. Configure these values as AppSail secrets/environment variables; never commit OAuth credentials:

```text
QUICKML_LLM_ENDPOINT_URL=<LLM Serving endpoint>
QUICKML_RAG_ENDPOINT_URL=<RAG endpoint, optional until enabled>
QUICKML_ORG_ID=<Catalyst organisation ID>
QUICKML_ENDPOINT_KEY=<deployed QuickML endpoint key>
QUICKML_OAUTH_ACCESS_TOKEN=<short-lived OAuth access token>
QUICKML_RAG_RECORD_DOCUMENT_MAP={"crime-number":"knowledge-base-document-id"}
```

Console configuration:

1. Confirm the organisation can open **QuickML > Generative AI**. Under **LLM Serving > Models**, deploy **Qwen 2.5-14B Instruct** (or the department-approved model) and copy its endpoint URL and endpoint key.
2. Generate a Zoho OAuth access token with `QuickML.deployment.READ` using Catalyst's documented LLM Serving OAuth flow. Store it in AppSail secrets and rotate/refresh it outside source control.
3. Under **Generative AI > Knowledge Base**, upload one access-controlled document per FIR/graph record. Create the RAG endpoint, then map every FIR `crime_no` to its returned Knowledge Base document ID in `QUICKML_RAG_RECORD_DOCUMENT_MAP`.
4. Keep separate role-authorised document collections/mappings where department policy requires them. The application filters the allowed record/document IDs before every RAG request and also validates every evidence ID returned by the model.

If the organisation does not yet have QuickML Generative AI/RAG access, leave `QUICKML_RAG_ENDPOINT_URL` and the document map unset. `intelligence_engine.py` then performs filtered retrieval in Flask and sends only the authorised records to Catalyst LLM Serving. If LLM Serving itself is unconfigured, case Q&A safely uses the existing deterministic evidence engine and cross-case analytics returns `503` instead of fabricating an answer.

AppSail automatically uses Catalyst Hosted Authentication. Override this with `CATALYST_AUTH_ENABLED=0` only for local development. The hosted login can be changed with `CATALYST_HOSTED_LOGIN_URL`.

The Catalyst ConvoKraft bot can be grounded with the public, non-sensitive reference corpus at `knowledge/crimegpt_training.txt`. Operational FIR documents remain in authenticated Catalyst Data Store/File Store and must not be published as SmartTrain material.

## ER-aligned FIR extraction

The intake screen provides `Extract fields for review` for searchable PDF and UTF-8 TXT sources. It maps labels to CaseMaster, ComplainantDetails, Victim, Accused, and ActSectionAssociation fields while preserving the original narrative. Language, extraction coverage, missing fields, source document, and verifying officer are recorded in `fir_extractions`.

Extraction is assistive: suggested fields remain visually marked until an officer verifies and submits them. Conservative person-name resolution can connect variants such as `R. Naik` and `Ravi Naik` without training a custom model.

Anonymised English, Kannada, and Hindi examples are available under `samples/`.

## Production controls

Cloud deployments do not load the bundled demo FIRs unless `SEED_DEMO_DATA=1` is explicitly set. Keep it `0` for every controlled or production environment.

Analysts and supervisors can import authorised UTF-8 CCTNS CSV/JSON extracts through `POST /api/admin/import-cctns`. The accepted column aliases and a synthetic mapping file are in `samples/cctns_import_template.csv`. Imports are validated, SHA-256 deduplicated and audited; malformed rows are rejected without being silently invented.

Operational endpoints are role protected:

- `GET /api/admin/permissions` — effective role permissions.
- `GET /api/model/evaluation` — validation status and labelled threshold metrics.
- `GET /api/metrics` — request latency/error telemetry for analysts and supervisors.
- `GET /api/admin/backup` — supervisor-only consistent snapshot.
- `POST /api/admin/retention` — supervisor-only audited conversation retention.

See `PRODUCTION_READINESS.md` for environment settings, load-test acceptance criteria, model validation, security operations and the external SCRB/legal approval gates.
