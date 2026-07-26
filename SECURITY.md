# Security and operational boundaries

CrimeGPT separates verified record facts from analytical leads. A link score is not proof of identity or guilt and always requires investigator review.

Production deployments must provide a random `SECRET_KEY`, HTTPS with `COOKIE_SECURE=1`, managed persistent storage, centralised log retention, secret rotation, backups, and organisation-managed identity. Demo accounts and passwords are for local evaluation only and must be disabled before operational data is loaded.

Access roles are enforced server-side. Investigators and analysts can ingest FIRs; investigators, analysts, and supervisors can use case intelligence; policymakers receive aggregate views only; audit access is limited to analysts and supervisors.

Uploaded documents are limited to 5 MB and searchable TXT/PDF input. Scanned documents require an approved OCR provider. Do not upload live personal or criminal records into the prototype environment.

Placeholder identities such as `Unknown A1` are intentionally excluded from person matching. Similar-name matches remain analytical leads until corroborated by a stable identifier or human review.
