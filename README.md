# CrimeGPT - KSP Crime Intelligence Platform

CrimeGPT is a Flask-based crime intelligence prototype for Datathon 2026 Problem Statement 1. It provides FIR intake, role-aware case access, relationship graphs, evidence-grounded queries, hotspot signals, and interactive investigation storylines.

## Features

- Persistent SQLite-backed FIR and relationship data
- Hashed demo authentication with role-aware navigation
- Multilingual FIR narrative intake through manual entry, PDF, or TXT upload
- Searchable case workspace and aggregate intelligence dashboard
- Interactive, draggable and zoomable investigation graphs
- Full-screen graph exploration and focused connection views
- Data-driven hotspot and repeat-offender colours
- Animated incident, offender, and hotspot storylines
- Record-level evidence trails and persistent audit events

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

## ER-aligned FIR extraction

The intake screen provides `Extract fields for review` for searchable PDF and UTF-8 TXT sources. It maps labels to CaseMaster, ComplainantDetails, Victim, Accused, and ActSectionAssociation fields while preserving the original narrative. Language, extraction coverage, missing fields, source document, and verifying officer are recorded in `fir_extractions`.

Extraction is assistive: suggested fields remain visually marked until an officer verifies and submits them. Conservative person-name resolution can connect variants such as `R. Naik` and `Ravi Naik` without training a custom model.

Anonymised English, Kannada, and Hindi examples are available under `samples/`.
