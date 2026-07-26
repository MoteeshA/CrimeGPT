# CrimeGPT analytical engine model card

## Current implementation

The current engine is an explainable deterministic retrieval and scoring system, not a trained predictive model or general-purpose LLM. It retrieves authorised FIR fields and calculates cross-case leads from conservative name similarity, offence category, geographic distance, and incident-time proximity.

## Intended use

Decision support for authorised investigators, prioritisation, and hypothesis generation. Outputs must be reviewed against original records and independent evidence.

## Prohibited use

Automated arrest, charging, surveillance, guilt determination, or adverse action. Demographic attributes must not be used as risk proxies.

## Known limitations

Name similarity can be ambiguous; incomplete records reduce recall; location proximity does not establish a relationship; sample data does not establish real-world model performance. Placeholder identities are excluded from matching.

## Required validation before production

Evaluate precision and recall on a de-identified, investigator-labelled link set; report false-positive rates by district and language; calibrate thresholds; test drift; document every feature and model version; preserve evidence and reviewer decisions in the audit trail.
