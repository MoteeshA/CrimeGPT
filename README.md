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
- Optional evidence-constrained model endpoint with deterministic evidence-engine fallback
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

Set `AI_ENDPOINT_URL` and, when required, `AI_API_KEY` to enable a private generative model. The model must return JSON containing `answer`, `kind`, `confidence`, and `evidence_ids`. Responses without authorised evidence IDs are rejected and the deterministic evidence engine is used instead.

AppSail automatically uses Catalyst Hosted Authentication. Override this with `CATALYST_AUTH_ENABLED=0` only for local development. The hosted login can be changed with `CATALYST_HOSTED_LOGIN_URL`.

## ER-aligned FIR extraction

The intake screen provides `Extract fields for review` for searchable PDF and UTF-8 TXT sources. It maps labels to CaseMaster, ComplainantDetails, Victim, Accused, and ActSectionAssociation fields while preserving the original narrative. Language, extraction coverage, missing fields, source document, and verifying officer are recorded in `fir_extractions`.

Extraction is assistive: suggested fields remain visually marked until an officer verifies and submits them. Conservative person-name resolution can connect variants such as `R. Naik` and `Ravi Naik` without training a custom model.

Anonymised English, Kannada, and Hindi examples are available under `samples/`.
