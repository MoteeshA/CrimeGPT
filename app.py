from datetime import datetime
from functools import wraps
from io import BytesIO
from pathlib import Path
import os
import sqlite3
import re
import unicodedata
import json
import csv
import hashlib
import logging
import secrets
import threading
from tempfile import NamedTemporaryFile
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen
from xml.sax.saxutils import escape
from difflib import SequenceMatcher
from math import asin, cos, radians, sin, sqrt
from flask import Flask, g, jsonify, redirect, render_template, request, session, url_for, send_file
from werkzeug.security import check_password_hash, generate_password_hash
from pypdf import PdfReader
from intelligence_engine import CatalystQuickMLEngine, classify_query


app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "local-development-key-change-in-production")
app.config["MAX_CONTENT_LENGTH"] = 5 * 1024 * 1024
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Strict",
    SESSION_COOKIE_SECURE=os.environ.get("COOKIE_SECURE") == "1",
    PERMANENT_SESSION_LIFETIME=1800,
)
logging.basicConfig(level=os.environ.get("LOG_LEVEL", "INFO"), format="%(asctime)s %(levelname)s %(message)s")
DB_PATH = Path(os.environ.get("DATABASE_PATH", Path(__file__).with_name("ksp_intelligence.db")))
CLOUD_SYNC_LOCK = threading.Lock()
CLOUD_HYDRATED = False
CATALYST_HOSTED_LOGIN_URL = os.environ.get(
    "CATALYST_HOSTED_LOGIN_URL",
    "https://crimegpt-60080077164.development.catalystserverless.in/__catalyst/auth/login",
).strip()


USERS = {
    "INV001": {"password": "demo123", "name": "Ananya Rao", "role": "investigator", "rank": "Police Inspector", "unit": "Central Police Station"},
    "ANL001": {"password": "demo123", "name": "Vikram Shetty", "role": "analyst", "rank": "Crime Analyst", "unit": "State Crime Records Bureau"},
    "SUP001": {"password": "demo123", "name": "Meera Nair", "role": "supervisor", "rank": "Superintendent of Police", "unit": "Bengaluru City"},
    "POL001": {"password": "demo123", "name": "Arun Kumar", "role": "policymaker", "rank": "Additional DGP", "unit": "Police Headquarters"},
}

CASES = [
    {"id": 417, "crime_no": "104430006202600417", "case_no": "202600417", "title": "Chain snatching near market", "category": "FIR", "major": "Crime Against Property", "minor": "Robbery", "status": "Under Investigation", "gravity": "Heinous", "station": "Central Police Station", "district": "Bengaluru Urban", "date": "18 Jul 2026", "time": "19:42", "location": "Avenue Road, Bengaluru", "lat": 12.9682, "lng": 77.5809, "officer": "Ananya Rao", "complainant": "Kavya M.", "victim": "Kavya M.", "accused": ["Ravi Naik", "Unknown A2"], "acts": ["BNS 309(4)", "BNS 3(5)"], "brief": "Two persons on a motorcycle allegedly snatched a gold chain and escaped toward Mysore Bank Circle.", "risk": 82},
    {"id": 388, "crime_no": "104430006202600388", "case_no": "202600388", "title": "Mobile phone snatching", "category": "FIR", "major": "Crime Against Property", "minor": "Robbery", "status": "Under Investigation", "gravity": "Non-Heinous", "station": "Central Police Station", "district": "Bengaluru Urban", "date": "09 Jul 2026", "time": "20:05", "location": "K.R. Market, Bengaluru", "lat": 12.9636, "lng": 77.5771, "officer": "Ananya Rao", "complainant": "Suresh P.", "victim": "Suresh P.", "accused": ["Ravi Naik"], "acts": ["BNS 304"], "brief": "Phone snatched by a motorcycle-borne offender near the bus stop.", "risk": 74},
    {"id": 219, "crime_no": "104430014202500219", "case_no": "202500219", "title": "Jewellery theft from pedestrian", "category": "FIR", "major": "Crime Against Property", "minor": "Theft", "status": "Charge Sheeted", "gravity": "Non-Heinous", "station": "Chickpet Police Station", "district": "Bengaluru Urban", "date": "22 Nov 2025", "time": "18:55", "location": "Chickpet Main Road, Bengaluru", "lat": 12.9701, "lng": 77.5753, "officer": "R. Prakash", "complainant": "Lakshmi D.", "victim": "Lakshmi D.", "accused": ["Ravi Naik", "Mahesh K."], "acts": ["BNS 303(2)"], "brief": "Jewellery taken from a pedestrian in a crowded commercial lane.", "risk": 65},
    {"id": 501, "crime_no": "104430021202600501", "case_no": "202600501", "title": "Night burglary at pharmacy", "category": "FIR", "major": "Crime Against Property", "minor": "Burglary", "status": "Under Investigation", "gravity": "Heinous", "station": "Ashok Nagar Police Station", "district": "Bengaluru Urban", "date": "21 Jul 2026", "time": "02:14", "location": "Richmond Road, Bengaluru", "lat": 12.9655, "lng": 77.6002, "officer": "S. Divya", "complainant": "Harish B.", "victim": "Harish B.", "accused": ["Unknown A1"], "acts": ["BNS 331(4)", "BNS 305"], "brief": "Rear shutter forced open; cash and controlled medicines reported missing.", "risk": 88},
]

AUDIT_LOG = []
REQUEST_METRICS = {"started_at": datetime.now().isoformat(), "requests": 0, "errors": 0, "total_ms": 0.0, "routes": {}}


def env_flag(name, default=False):
    value = os.environ.get(name)
    return default if value is None else value.strip().lower() in {"1", "true", "yes", "on"}


def demo_seed_enabled():
    """Demo identities and FIRs must never silently enter a cloud deployment."""
    return env_flag("SEED_DEMO_DATA", not catalyst_enabled())


def get_db():
    connection = sqlite3.connect(DB_PATH, timeout=30)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    connection.execute("PRAGMA busy_timeout = 30000")
    return connection


def catalyst_enabled():
    return os.environ.get("CATALYST_CLOUD_ENABLED", "").lower() in {"1", "true", "yes"} or bool(os.environ.get("X_ZOHO_CATALYST_LISTEN_PORT"))


def catalyst_app():
    """Return the request-scoped Catalyst SDK app, or None outside Catalyst."""
    if not catalyst_enabled():
        return None
    if "catalyst_app" in g:
        return g.catalyst_app
    try:
        import zcatalyst_sdk
        try:
            g.catalyst_app = zcatalyst_sdk.get_app()
        except Exception:
            g.catalyst_app = zcatalyst_sdk.initialize(req=request)
        return g.catalyst_app
    except Exception as exc:
        app.logger.warning("Catalyst SDK is unavailable for %s: %s", request.path, exc)
        g.catalyst_app = None
        return None


def cloud_rows(table_name):
    cloud = catalyst_app()
    if not cloud:
        return []
    return list(cloud.datastore().table(table_name).get_iterable_rows())


def cloud_upsert(table_name, external_id, payload):
    """Persist an ER-aligned JSON record in Catalyst Data Store."""
    cloud = catalyst_app()
    if not cloud:
        return False
    table = cloud.datastore().table(table_name)
    encoded = json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
    existing = next((row for row in table.get_iterable_rows() if str(row.get("ExternalID")) == str(external_id)), None)
    if existing:
        table.update_row({"ROWID": existing["ROWID"], "ExternalID": str(external_id), "Payload": encoded})
    else:
        table.insert_row({"ExternalID": str(external_id), "Payload": encoded})
    return True


def cloud_upload(upload, filename):
    folder_id = os.environ.get("DOCUMENT_FOLDER_REF", "56313000000019211").strip()
    cloud = catalyst_app()
    if not cloud or not folder_id or not upload:
        return None
    upload.stream.seek(0)
    with NamedTemporaryFile() as temporary:
        temporary.write(upload.stream.read())
        temporary.flush()
        with open(temporary.name, "rb") as buffered_file:
            result = cloud.filestore().folder(folder_id).upload_file(filename, buffered_file)
    upload.stream.seek(0)
    return str(result.get("id") or result.get("file_id") or "") or None


def init_db():
    with get_db() as db:
        db.executescript("""
            CREATE TABLE IF NOT EXISTS users (
                officer_id TEXT PRIMARY KEY,
                password_hash TEXT NOT NULL,
                name TEXT NOT NULL,
                role TEXT NOT NULL CHECK(role IN ('investigator','analyst','supervisor','policymaker')),
                rank_name TEXT NOT NULL,
                unit_name TEXT NOT NULL,
                active INTEGER NOT NULL DEFAULT 1
            );
            CREATE TABLE IF NOT EXISTS cases (
                id INTEGER PRIMARY KEY,
                crime_no TEXT NOT NULL UNIQUE,
                case_no TEXT NOT NULL,
                title TEXT NOT NULL,
                category TEXT NOT NULL,
                major_head TEXT NOT NULL,
                minor_head TEXT NOT NULL,
                status TEXT NOT NULL,
                gravity TEXT NOT NULL,
                station TEXT NOT NULL,
                district TEXT NOT NULL,
                incident_date TEXT NOT NULL,
                incident_time TEXT NOT NULL,
                location TEXT NOT NULL,
                latitude REAL,
                longitude REAL,
                officer TEXT NOT NULL,
                complainant TEXT,
                victim TEXT,
                brief_facts TEXT,
                risk_score INTEGER NOT NULL DEFAULT 0
            );
            CREATE TABLE IF NOT EXISTS accused (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                canonical_name TEXT NOT NULL,
                identity_key TEXT NOT NULL UNIQUE
            );
            CREATE TABLE IF NOT EXISTS case_accused (
                case_id INTEGER NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
                accused_id INTEGER NOT NULL REFERENCES accused(id),
                person_order INTEGER NOT NULL,
                PRIMARY KEY(case_id, accused_id)
            );
            CREATE TABLE IF NOT EXISTS case_acts (
                case_id INTEGER NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
                act_section TEXT NOT NULL,
                PRIMARY KEY(case_id, act_section)
            );
            CREATE TABLE IF NOT EXISTS audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                occurred_at TEXT NOT NULL,
                officer_id TEXT NOT NULL,
                role TEXT NOT NULL,
                action TEXT NOT NULL,
                resource TEXT NOT NULL,
                detail TEXT
            );
            CREATE TABLE IF NOT EXISTS fir_extractions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                case_id INTEGER REFERENCES cases(id) ON DELETE SET NULL,
                source_document TEXT,
                source_language TEXT NOT NULL,
                extraction_confidence INTEGER NOT NULL,
                missing_fields TEXT,
                verified_by TEXT,
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS conversations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                case_id INTEGER NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
                officer_id TEXT NOT NULL REFERENCES users(officer_id),
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS conversation_messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                conversation_id INTEGER NOT NULL REFERENCES conversations(id) ON DELETE CASCADE,
                role TEXT NOT NULL CHECK(role IN ('user','assistant')),
                content TEXT NOT NULL,
                language TEXT NOT NULL,
                kind TEXT,
                confidence INTEGER,
                evidence_json TEXT,
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS import_jobs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                checksum TEXT NOT NULL UNIQUE,
                source_name TEXT NOT NULL,
                imported_by TEXT NOT NULL,
                accepted INTEGER NOT NULL,
                rejected INTEGER NOT NULL,
                errors_json TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS model_predictions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                case_id INTEGER NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
                model_version TEXT NOT NULL,
                score INTEGER NOT NULL,
                features_json TEXT NOT NULL,
                explanation_json TEXT NOT NULL,
                outcome INTEGER,
                created_at TEXT NOT NULL
            );
        """)
        if demo_seed_enabled() and db.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 0:
            db.executemany(
                "INSERT OR IGNORE INTO users VALUES (?, ?, ?, ?, ?, ?, 1)",
                [(officer_id, generate_password_hash(item["password"], method="pbkdf2:sha256"), item["name"], item["role"], item["rank"], item["unit"]) for officer_id, item in USERS.items()],
            )
        if demo_seed_enabled() and db.execute("SELECT COUNT(*) FROM cases").fetchone()[0] == 0:
            for case in CASES:
                db.execute("""INSERT OR IGNORE INTO cases VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""", (
                    case["id"], case["crime_no"], case["case_no"], case["title"], case["category"], case["major"], case["minor"],
                    case["status"], case["gravity"], case["station"], case["district"], case["date"], case["time"], case["location"],
                    case["lat"], case["lng"], case["officer"], case["complainant"], case["victim"], case["brief"], case["risk"],
                ))
                for order, name in enumerate(case["accused"], 1):
                    identity_key = "".join(character for character in name.lower() if character.isalnum())
                    db.execute("INSERT OR IGNORE INTO accused(canonical_name, identity_key) VALUES (?, ?)", (name, identity_key))
                    accused_id = db.execute("SELECT id FROM accused WHERE identity_key = ?", (identity_key,)).fetchone()[0]
                    db.execute("INSERT OR IGNORE INTO case_accused VALUES (?, ?, ?)", (case["id"], accused_id, order))
                db.executemany("INSERT OR IGNORE INTO case_acts VALUES (?, ?)", [(case["id"], act) for act in case["acts"]])
        columns = {row[1] for row in db.execute("PRAGMA table_info(cases)")}
        if "source_language" not in columns:
            db.execute("ALTER TABLE cases ADD COLUMN source_language TEXT NOT NULL DEFAULT 'English'")
        if "source_document" not in columns:
            db.execute("ALTER TABLE cases ADD COLUMN source_document TEXT")


def case_from_row(row, db=None):
    owns_connection = db is None
    db = db or get_db()
    data = dict(row)
    data.update({
        "major": data.pop("major_head"), "minor": data.pop("minor_head"), "date": data.pop("incident_date"),
        "time": data.pop("incident_time"), "lat": data.pop("latitude"), "lng": data.pop("longitude"),
        "brief": data.pop("brief_facts"), "risk": data.pop("risk_score"),
    })
    if str(data.get("brief", "")).startswith("PUBLIC-RECORD REFERENCE"):
        data["risk"] = -1
    data["accused"] = [item[0] for item in db.execute("SELECT a.canonical_name FROM accused a JOIN case_accused ca ON ca.accused_id=a.id WHERE ca.case_id=? ORDER BY ca.person_order", (data["id"],))]
    data["acts"] = [item[0] for item in db.execute("SELECT act_section FROM case_acts WHERE case_id=? ORDER BY act_section", (data["id"],))]
    if owns_connection:
        db.close()
    return data


def persist_case_to_cloud(case_id):
    case = find_case(case_id)
    if case:
        cloud_upsert("CaseMaster", case["crime_no"], case)


def hydrate_cases_from_cloud():
    """Hydrate the local query cache once per worker from persistent Data Store."""
    global CLOUD_HYDRATED
    if CLOUD_HYDRATED or not catalyst_enabled():
        return
    with CLOUD_SYNC_LOCK:
        if CLOUD_HYDRATED:
            return
        rows = cloud_rows("CaseMaster")
        with get_db() as db:
            for row in rows:
                try:
                    case = json.loads(row.get("Payload") or "{}")
                    if not case.get("id") or not case.get("crime_no"):
                        continue
                    db.execute("""INSERT OR REPLACE INTO cases(id,crime_no,case_no,title,category,major_head,minor_head,status,gravity,station,district,incident_date,incident_time,location,latitude,longitude,officer,complainant,victim,brief_facts,risk_score,source_language,source_document)
                        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""", (
                        case["id"], case["crime_no"], case.get("case_no", ""), case.get("title", "Untitled FIR"), case.get("category", "FIR"),
                        case.get("major", "Other"), case.get("minor", "Other"), case.get("status", "Under Investigation"), case.get("gravity", "Non-Heinous"),
                        case.get("station", ""), case.get("district", ""), case.get("date", ""), case.get("time", ""), case.get("location", ""),
                        case.get("lat"), case.get("lng"), case.get("officer", ""), case.get("complainant", ""), case.get("victim", ""), case.get("brief", ""),
                        -1 if str(case.get("brief", "")).startswith("PUBLIC-RECORD REFERENCE") else case.get("risk", -1), case.get("source_language", "English"), case.get("source_document"),
                    ))
                    db.execute("DELETE FROM case_accused WHERE case_id=?", (case["id"],))
                    db.execute("DELETE FROM case_acts WHERE case_id=?", (case["id"],))
                    for order, name in enumerate(case.get("accused", []), 1):
                        accused_id, _, _ = resolve_accused(db, name)
                        db.execute("INSERT OR IGNORE INTO case_accused VALUES (?,?,?)", (case["id"], accused_id, order))
                    db.executemany("INSERT OR IGNORE INTO case_acts VALUES (?,?)", [(case["id"], act) for act in case.get("acts", [])])
                except (KeyError, TypeError, ValueError, sqlite3.Error):
                    app.logger.exception("Skipped invalid Catalyst CaseMaster row %s", row.get("ROWID"))
        CLOUD_HYDRATED = True
        app.logger.info("Hydrated %s CaseMaster records from Catalyst Data Store", len(rows))


def catalyst_auth_enabled():
    """Use Catalyst identities in AppSail; retain demo accounts only for local development/tests."""
    configured = os.environ.get("CATALYST_AUTH_ENABLED")
    return catalyst_enabled() if configured is None else configured.lower() in {"1", "true", "yes"}


def catalyst_current_user():
    cached_identity = session.get("catalyst_identity")
    if cached_identity:
        return cached_identity
    if getattr(g, "_catalyst_identity_checked", False):
        return getattr(g, "_catalyst_identity", None)
    g._catalyst_identity_checked = True
    g._catalyst_identity = None
    if not catalyst_auth_enabled() or not catalyst_enabled():
        return None
    try:
        identity = catalyst_app().authentication().get_current_user()
        if not identity or str(identity.get("status", "")).upper() not in {"ACTIVE", ""}:
            return None
        role_name = str((identity.get("role_details") or {}).get("role_name", "App User")).lower()
        role = {
            "app administrator": "supervisor",
            "investigator": "investigator",
            "analyst": "analyst",
            "supervisor": "supervisor",
            "policymaker": "policymaker",
            "app user": "investigator",
        }.get(role_name, "investigator")
        name = " ".join(filter(None, [identity.get("first_name"), identity.get("last_name")])).strip()
        g._catalyst_identity = {
            "id": str(identity.get("user_id") or identity.get("zuid") or identity.get("email_id")),
            "name": name or identity.get("email_id") or "Authorised user",
            "email": identity.get("email_id"),
            "role": role,
            "rank": (identity.get("role_details") or {}).get("role_name", "App User"),
            "unit": "Karnataka State Police",
            "auth_source": "catalyst",
        }
        session["catalyst_identity"] = g._catalyst_identity
        return g._catalyst_identity
    except Exception as exc:
        app.logger.info("No authenticated Catalyst end-user for %s: %s", request.path, exc)
        return None


def current_user():
    cloud_user = catalyst_current_user()
    if cloud_user:
        return cloud_user
    if catalyst_auth_enabled():
        return None
    officer_id = session.get("officer_id")
    if not officer_id:
        return None
    with get_db() as db:
        row = db.execute("SELECT * FROM users WHERE officer_id=? AND active=1", (officer_id,)).fetchone()
    if not row:
        return None
    return {"id": row["officer_id"], "name": row["name"], "role": row["role"], "rank": row["rank_name"], "unit": row["unit_name"]}


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not current_user():
            return redirect(url_for("login"))
        return view(*args, **kwargs)
    return wrapped


def roles_required(*allowed_roles):
    def decorator(view):
        @wraps(view)
        @login_required
        def wrapped(*args, **kwargs):
            user = current_user()
            if user["role"] not in allowed_roles:
                audit("ACCESS_DENIED", request.path, f"required={','.join(allowed_roles)}")
                if request.path.startswith("/api/"):
                    return jsonify({"error": "Forbidden"}), 403
                return "Forbidden", 403
            return view(*args, **kwargs)
        return wrapped
    return decorator


def csrf_token():
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_urlsafe(32)
    return session["csrf_token"]


@app.before_request
def enforce_request_security():
    g.request_started = datetime.now()
    if catalyst_enabled():
        try:
            catalyst_app()
            hydrate_cases_from_cloud()
        except Exception:
            app.logger.exception("Catalyst persistence initialization failed")
    if request.method in {"POST", "PUT", "PATCH", "DELETE"} and not app.config.get("TESTING"):
        supplied = request.headers.get("X-CSRF-Token") or request.form.get("csrf_token")
        expected = session.get("csrf_token")
        if not expected or not secrets.compare_digest(supplied or "", expected):
            audit("CSRF_REJECTED", request.path, request.remote_addr or "unknown")
            return (jsonify({"error": "Invalid or expired security token"}), 400) if request.path.startswith("/api/") else ("Invalid or expired security token", 400)


@app.after_request
def secure_response(response):
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "same-origin")
    response.headers.setdefault("Permissions-Policy", "camera=(), geolocation=(), microphone=(self)")
    response.headers.setdefault("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline' https://static.zohocdn.com; img-src 'self' data:; connect-src 'self'; font-src 'self'; frame-ancestors 'none'")
    if request.path.startswith("/api/") or request.path in {"/health", "/ready"}:
        response.headers.setdefault("Cache-Control", "no-store")
    elapsed = max(0.0, (datetime.now() - getattr(g, "request_started", datetime.now())).total_seconds() * 1000)
    REQUEST_METRICS["requests"] += 1
    REQUEST_METRICS["total_ms"] += elapsed
    if response.status_code >= 500:
        REQUEST_METRICS["errors"] += 1
    route = request.url_rule.rule if request.url_rule else "unmatched"
    route_metrics = REQUEST_METRICS["routes"].setdefault(route, {"count": 0, "errors": 0, "total_ms": 0.0})
    route_metrics["count"] += 1
    route_metrics["total_ms"] += elapsed
    route_metrics["errors"] += int(response.status_code >= 500)
    response.headers.setdefault("Server-Timing", f"app;dur={elapsed:.1f}")
    return response


@app.get("/health")
def health():
    return jsonify({"status": "ok", "service": "crimegpt"})


@app.get("/ready")
def ready():
    try:
        with get_db() as db:
            db.execute("SELECT 1").fetchone()
        cloud_status = "disabled"
        if catalyst_enabled():
            try:
                catalyst_app().datastore().table("CaseMaster").get_paged_rows(max_rows=1)
                cloud_status = "available"
            except Exception:
                cloud_status = "unavailable"
        status = "ready" if cloud_status != "unavailable" else "degraded"
        return jsonify({"status": status, "database": "available", "catalyst_datastore": cloud_status}), 200 if status == "ready" else 503
    except sqlite3.Error:
        app.logger.exception("Readiness database check failed")
        return jsonify({"status": "not-ready", "database": "unavailable"}), 503


@app.get("/api/metrics")
@roles_required("supervisor", "analyst")
def metrics():
    routes = {name: {**values, "average_ms": round(values["total_ms"] / max(values["count"], 1), 2)} for name, values in REQUEST_METRICS["routes"].items()}
    return jsonify({**REQUEST_METRICS, "average_ms": round(REQUEST_METRICS["total_ms"] / max(REQUEST_METRICS["requests"], 1), 2), "routes": routes})


@app.errorhandler(413)
def upload_too_large(_error):
    return (jsonify({"error": "File exceeds the 5 MB upload limit"}), 413) if request.path.startswith("/api/") else ("File exceeds the 5 MB upload limit", 413)


@app.errorhandler(500)
def internal_error(error):
    app.logger.error("Unhandled request error on %s: %s", request.path, error)
    return (jsonify({"error": "Internal service error", "request_path": request.path}), 500) if request.path.startswith("/api/") else ("Internal service error. The incident has been logged.", 500)


def audit(action, resource, detail=""):
    user = current_user()
    if user:
        occurred_at = datetime.now().isoformat(timespec="microseconds")
        event = {"occurred_at": occurred_at, "officer_id": user["id"], "role": user["role"], "action": action, "resource": resource, "detail": detail}
        with get_db() as db:
            db.execute("INSERT INTO audit_log(occurred_at,officer_id,role,action,resource,detail) VALUES (?,?,?,?,?,?)", tuple(event.values()))
        if os.environ.get("SYNC_AUDIT_TO_CLOUD", "").lower() in {"1", "true", "yes"}:
            try:
                cloud_upsert("AuditEvents", f"{occurred_at}:{secrets.token_hex(4)}", event)
            except Exception:
                app.logger.exception("Could not mirror audit event to Catalyst")


def active_conversation(case_id, create=True):
    user = current_user()
    if not user:
        return None
    with get_db() as db:
        if user.get("auth_source") == "catalyst":
            db.execute(
                """INSERT OR IGNORE INTO users(officer_id,password_hash,name,role,rank_name,unit_name,active)
                   VALUES (?,?,?,?,?,?,1)""",
                (user["id"], "CATALYST_MANAGED", user["name"], user["role"], user["rank"], user["unit"]),
            )
        row = db.execute("SELECT * FROM conversations WHERE case_id=? AND officer_id=? ORDER BY updated_at DESC LIMIT 1", (case_id, user["id"])).fetchone()
        if not row and create:
            now = datetime.now().isoformat(timespec="seconds")
            cursor = db.execute("INSERT INTO conversations(case_id,officer_id,created_at,updated_at) VALUES (?,?,?,?)", (case_id, user["id"], now, now))
            row = db.execute("SELECT * FROM conversations WHERE id=?", (cursor.lastrowid,)).fetchone()
        return dict(row) if row else None


def conversation_history(conversation_id):
    with get_db() as db:
        rows = db.execute("SELECT * FROM conversation_messages WHERE conversation_id=? ORDER BY id", (conversation_id,)).fetchall()
    return [{**dict(row), "evidence": json.loads(row["evidence_json"] or "[]")} for row in rows]


def store_message(conversation_id, role, content, language, kind=None, confidence=None, evidence=None):
    now = datetime.now().isoformat(timespec="seconds")
    with get_db() as db:
        db.execute("INSERT INTO conversation_messages(conversation_id,role,content,language,kind,confidence,evidence_json,created_at) VALUES (?,?,?,?,?,?,?,?)", (conversation_id, role, content, language, kind, confidence, json.dumps(evidence or [], ensure_ascii=False), now))
        db.execute("UPDATE conversations SET updated_at=? WHERE id=?", (now, conversation_id))
    try:
        cloud_upsert("Conversations", f"{conversation_id}:{now}:{role}", {"conversation_id": conversation_id, "role": role, "content": content, "language": language, "kind": kind, "confidence": confidence, "evidence": evidence or [], "created_at": now})
    except Exception:
        app.logger.exception("Could not mirror conversation message to Catalyst")


def find_case(case_id):
    with get_db() as db:
        row = db.execute("SELECT * FROM cases WHERE id=?", (case_id,)).fetchone()
        return case_from_row(row, db) if row else None


def linked_cases(case_id):
    with get_db() as db:
        source_row = db.execute("SELECT * FROM cases WHERE id=?", (case_id,)).fetchone()
        if not source_row:
            return []
        source = case_from_row(source_row, db)
        candidates = []
        for row in db.execute("SELECT * FROM cases WHERE id<>?", (case_id,)).fetchall():
            candidate = case_from_row(row, db)
            reasons, evidence, score = [], [], 0
            person_matches = []
            for source_name in source["accused"]:
                for candidate_name in candidate["accused"]:
                    similarity = person_name_score(source_name, candidate_name)
                    if similarity >= 88:
                        person_matches.append((source_name, candidate_name, similarity))
            if person_matches:
                best = max(person_matches, key=lambda item: item[2])
                score += round(best[2] * .65)
                reasons.append(f"accused identity {best[2]}%")
                evidence.append({"table": "Accused", "field": "AccusedName", "value": f"{best[0]} ↔ {best[1]}"})
            if source["minor"].casefold() == candidate["minor"].casefold():
                score += 15
                reasons.append("same crime sub-head")
                evidence.append({"table": "CrimeSubHead", "field": "CrimeHeadName", "value": source["minor"]})
            if all((source["lat"], source["lng"], candidate["lat"], candidate["lng"])):
                distance = distance_km(source["lat"], source["lng"], candidate["lat"], candidate["lng"])
                if distance <= 5:
                    score += max(3, round(10 - distance))
                    reasons.append(f"{distance:.1f} km apart")
                    evidence.append({"table": "CaseMaster", "field": "latitude/longitude", "value": f"{distance:.1f} km"})
            try:
                source_hour, candidate_hour = int(source["time"][:2]), int(candidate["time"][:2])
                hour_gap = min(abs(source_hour - candidate_hour), 24 - abs(source_hour - candidate_hour))
                if hour_gap <= 2:
                    score += 10 - hour_gap * 2
                    reasons.append("similar time window")
                    evidence.append({"table": "CaseMaster", "field": "IncidentFromDate", "value": f"{source['time']} ↔ {candidate['time']}"})
            except (TypeError, ValueError):
                pass
            if score >= 55:
                candidate.update({"link_score": min(score, 100), "link_reasons": reasons, "link_evidence": evidence})
                candidates.append(candidate)
        return sorted(candidates, key=lambda item: (item["link_score"], item["date"]), reverse=True)


def board_payload(case):
    with get_db() as db:
        accused_counts = {}
        for name in case["accused"]:
            accused_counts[name] = db.execute("""SELECT COUNT(DISTINCT ca.case_id) FROM case_accused ca JOIN accused a ON a.id=ca.accused_id WHERE lower(a.canonical_name)=lower(?)""", (name,)).fetchone()[0]
        offence_count = db.execute("SELECT COUNT(*) FROM cases WHERE lower(minor_head)=lower(?)", (case["minor"],)).fetchone()[0]
        person_count = db.execute("SELECT COUNT(*) FROM cases WHERE lower(victim)=lower(?) OR lower(complainant)=lower(?)", (case["victim"], case["victim"])).fetchone()[0]
        nearby_count = 0
        for row in db.execute("SELECT latitude,longitude FROM cases WHERE latitude IS NOT NULL AND longitude IS NOT NULL"):
            if distance_km(case["lat"], case["lng"], row["latitude"], row["longitude"]) <= 5:
                nearby_count += 1

    def signal_level(count, elevated=2, critical=3):
        return "critical" if count >= critical else "elevated" if count >= elevated else "normal"

    dense = len(case["accused"]) > 8
    nodes = [
        {"id": f"case-{case['id']}", "type": "case", "signal": "normal", "has_connections": False, "label": f"FIR {case['case_no']}", "meta": case["minor"], "value": str(case["id"]), "x": 50, "y": 45},
        {"id": f"place-{case['id']}", "type": "location", "signal": signal_level(nearby_count, 2, 4), "has_connections": nearby_count > 1, "label": case["location"], "meta": f"{nearby_count} FIRs within 5 km", "value": str(case["id"]), "x": 19, "y": 22},
        {"id": f"offence-{case['id']}", "type": "offence", "signal": signal_level(offence_count, 2, 4), "has_connections": offence_count > 1, "label": case["minor"], "meta": f"{offence_count} recorded FIRs", "value": case["minor"], "x": 50, "y": 82},
        {"id": f"victim-{case['id']}", "type": "victim", "signal": signal_level(person_count, 2, 3), "has_connections": person_count > 1, "label": case["victim"], "meta": f"{person_count} linked FIR · victim / complainant", "value": case["victim"], "x": 18, "y": 70},
    ]
    edges = [
        {"from": f"case-{case['id']}", "to": f"place-{case['id']}", "label": "occurred at"},
        {"from": f"case-{case['id']}", "to": f"victim-{case['id']}", "label": "reported by"},
        {"from": f"case-{case['id']}", "to": f"offence-{case['id']}", "label": "classified as"},
    ]
    if dense:
        positions = [(x, y) for y in (10, 26, 42, 58, 74, 90) for x in (64, 80, 94)]
    else:
        positions = [(80, 22), (82, 68), (52, 84)]
    for index, accused in enumerate(case["accused"]):
        node_id = f"accused-{case['id']}-{index}"
        count = accused_counts[accused]
        position = positions[index % len(positions)]
        nodes.append({"id": node_id, "type": "accused", "signal": signal_level(count, 2, 3), "has_connections": count > 1, "dense": dense, "compact": index < 6, "label": accused, "meta": f"A{index + 1} · {count} linked FIR{'s' if count != 1 else ''}", "value": accused, "x": position[0], "y": position[1]})
        edges.append({"from": f"case-{case['id']}", "to": node_id, "label": "accused in", "compact": index < 6})
    return {"nodes": nodes, "edges": edges, "dense": dense}


def distance_km(lat1, lng1, lat2, lng2):
    earth_radius = 6371
    d_lat, d_lng = radians(lat2 - lat1), radians(lng2 - lng1)
    value = sin(d_lat / 2) ** 2 + cos(radians(lat1)) * cos(radians(lat2)) * sin(d_lng / 2) ** 2
    return 2 * earth_radius * asin(sqrt(value))


def detect_language(text):
    scripts = {
        "Kannada": (0x0C80, 0x0CFF), "Hindi": (0x0900, 0x097F), "Tamil": (0x0B80, 0x0BFF),
        "Telugu": (0x0C00, 0x0C7F), "Malayalam": (0x0D00, 0x0D7F), "Bengali": (0x0980, 0x09FF),
        "Gujarati": (0x0A80, 0x0AFF), "Gurmukhi": (0x0A00, 0x0A7F), "Urdu/Arabic": (0x0600, 0x06FF),
    }
    counts = {name: sum(start <= ord(char) <= end for char in text) for name, (start, end) in scripts.items()}
    language, count = max(counts.items(), key=lambda item: item[1], default=("English", 0))
    return language if count else "English / Latin script"


FIELD_PATTERNS = {
    "crime_no": [r"(?:crime\s*(?:no|number)|ಅಪರಾಧ\s*ಸಂಖ್ಯೆ|अपराध\s*संख्या)\s*[:\-]\s*([A-Z0-9/\-]+)"],
    "case_no": [r"(?:case\s*(?:no|number)|ಪ್ರಕರಣ\s*ಸಂಖ್ಯೆ|मामला\s*संख्या)\s*[:\-]\s*([A-Z0-9/\-]+)"],
    "title": [r"(?:case\s*title|ಶೀರ್ಷಿಕೆ|शीर्षक)\s*[:\-]\s*([^\n\r]+)"],
    "major": [r"(?:major\s*(?:crime\s*)?head|ಪ್ರಮುಖ\s*ಅಪರಾಧ|प्रमुख\s*अपराध)\s*[:\-]\s*([^\n\r]+)"],
    "minor": [r"(?:minor\s*(?:crime\s*)?head|offence|ಅಪರಾಧದ\s*ವಿಧ|अपराध\s*प्रकार)\s*[:\-]\s*([^\n\r]+)"],
    "gravity": [r"(?:gravity|ಗಂಭೀರತೆ|गंभीरता)\s*[:\-]\s*(heinous|non[\s-]*heinous|ಘೋರ|ಅಘೋರ|जघन्य|गैर[\s-]*जघन्य)"],
    "station": [r"(?:police\s*station|ಠಾಣೆ|पुलिस\s*थाना)\s*[:\-]\s*([^\n\r]+)"],
    "district": [r"(?:district|ಜಿಲ್ಲೆ|जिला)\s*[:\-]\s*([^\n\r]+)"],
    "incident_date": [r"(?:incident\s*date|date\s*of\s*occurrence|ಘಟನೆಯ\s*ದಿನಾಂಕ|घटना\s*दिनांक)\s*[:\-]\s*([^\n\r]+)"],
    "incident_time": [r"(?:incident\s*time|time\s*of\s*occurrence|ಘಟನೆಯ\s*ಸಮಯ|घटना\s*समय)\s*[:\-]\s*([0-2]?\d[:.]\d{2}(?:\s*[AP]M)?)"],
    "location": [r"(?:location|place\s*of\s*occurrence|ಘಟನಾ\s*ಸ್ಥಳ|घटना\s*स्थल)\s*[:\-]\s*([^\n\r]+)"],
    "complainant": [r"(?:complainant|ದೂರುದಾರ|शिकायतकर्ता)\s*[:\-]\s*([^\n\r]+)"],
    "victim": [r"(?:victim|ಪೀಡಿತ|पीड़ित)\s*[:\-]\s*([^\n\r]+)"],
    "accused": [r"(?:accused|ಆರೋಪಿ|आरोपी)\s*[:\-]\s*([^\n\r]+)"],
    "acts": [r"(?:acts?\s*(?:and|&)\s*sections?|sections?|ಕಾಯ್ದೆ\s*ಮತ್ತು\s*ಕಲಂಗಳು|धारा)\s*[:\-]\s*([^\n\r]+)"],
}


def extract_fir_fields(text):
    """Assistive, deterministic extraction. Every value remains unverified until officer submission."""
    clean = unicodedata.normalize("NFKC", text or "").replace("\u00a0", " ")
    fields, evidence = {}, {}
    for field, patterns in FIELD_PATTERNS.items():
        for pattern in patterns:
            match = re.search(pattern, clean, flags=re.IGNORECASE)
            if match:
                value = re.sub(r"\s+", " ", match.group(1)).strip(" .;,")
                if field == "gravity":
                    value = "Non-Heinous" if re.search(r"non|ಅಘೋರ|गैर", value, re.I) else "Heinous"
                fields[field] = value
                evidence[field] = match.group(0).strip()
                break
    required = ("title", "major", "minor", "gravity", "station", "district", "incident_date", "incident_time", "location", "complainant", "acts")
    if fields.get("incident_date"):
        fields["incident_date"] = normalized_form_date(fields["incident_date"])
    if fields.get("incident_time"):
        fields["incident_time"] = normalized_form_time(fields["incident_time"])
    missing = [field for field in required if not fields.get(field)]
    confidence = round(100 * len(fields) / len(FIELD_PATTERNS))
    return {"language": detect_language(clean), "fields": fields, "evidence": evidence, "missing": missing, "confidence": confidence, "requires_officer_verification": True}


def normalize_person_name(name):
    value = unicodedata.normalize("NFKD", name or "").casefold()
    value = re.sub(r"\b(?:mr|mrs|ms|sri|smt|shri|dr|unknown|accused)\.?\b", " ", value)
    return " ".join(re.findall(r"[^\W\d_]+", value, flags=re.UNICODE))


def is_placeholder_identity(name):
    value = unicodedata.normalize("NFKC", name or "").casefold().strip()
    return bool(re.fullmatch(r"(?:unknown|unidentified|not\s+known|ತಿಳಿಯದ|ಅಪರಿಚಿತ|अज्ञात)(?:\s+(?:accused|person|suspect))?\s*[a-z]*\d*", value))


def person_name_score(left, right):
    if is_placeholder_identity(left) or is_placeholder_identity(right):
        return 0
    a, b = normalize_person_name(left), normalize_person_name(right)
    if not a or not b:
        return 0
    if a == b:
        return 100
    a_tokens, b_tokens = set(a.split()), set(b.split())
    token_score = len(a_tokens & b_tokens) / max(1, len(a_tokens | b_tokens))
    sequence_score = SequenceMatcher(None, a, b).ratio()
    initial_match = a.split()[0][0] == b.split()[0][0] and a.split()[-1] == b.split()[-1]
    return round(100 * max(token_score, sequence_score, .88 if initial_match else 0))


def resolve_accused(db, name):
    if is_placeholder_identity(name):
        identity_key = "placeholder-" + re.sub(r"\W+", "", unicodedata.normalize("NFKC", name).casefold())
        db.execute("INSERT OR IGNORE INTO accused(canonical_name,identity_key) VALUES (?,?)", (name, identity_key))
        row = db.execute("SELECT id,canonical_name FROM accused WHERE identity_key=?", (identity_key,)).fetchone()
        return row["id"], row["canonical_name"], 0
    candidates = db.execute("SELECT id,canonical_name FROM accused").fetchall()
    scored = sorted(((person_name_score(name, row["canonical_name"]), row) for row in candidates), key=lambda item: item[0], reverse=True)
    if scored and scored[0][0] >= 88:
        return scored[0][1]["id"], scored[0][1]["canonical_name"], scored[0][0]
    identity_key = normalize_person_name(name).replace(" ", "") or re.sub(r"\W+", "", name.casefold())
    db.execute("INSERT OR IGNORE INTO accused(canonical_name,identity_key) VALUES (?,?)", (name, identity_key))
    row = db.execute("SELECT id,canonical_name FROM accused WHERE identity_key=?", (identity_key,)).fetchone()
    return row["id"], row["canonical_name"], 100


def extract_document(upload):
    if not upload or not upload.filename:
        return "", None
    filename = upload.filename.rsplit("/", 1)[-1].rsplit("\\", 1)[-1]
    extension = Path(filename).suffix.lower()
    if extension == ".txt":
        return upload.read().decode("utf-8", errors="replace"), filename
    if extension == ".pdf":
        reader = PdfReader(upload.stream)
        return "\n".join(page.extract_text() or "" for page in reader.pages), filename
    raise ValueError("Only UTF-8 text and searchable PDF files are supported.")


def normalized_form_date(value):
    value = (value or "").strip()
    for fmt in ("%Y-%m-%d", "%d/%m/%Y", "%d-%m-%Y", "%d %b %Y", "%d %B %Y"):
        try:
            return datetime.strptime(value, fmt).strftime("%Y-%m-%d")
        except ValueError:
            continue
    return value


def normalized_form_time(value):
    value = (value or "").strip().replace(".", ":")
    for fmt in ("%H:%M", "%I:%M %p"):
        try:
            return datetime.strptime(value.upper(), fmt).strftime("%H:%M")
        except ValueError:
            continue
    return value


CCTNS_FIELD_ALIASES = {
    "crime_no": ("crime_no", "crime_number", "fir_no", "firnumber"),
    "case_no": ("case_no", "case_number"),
    "title": ("title", "case_title", "fir_title"),
    "major": ("major", "major_head", "majorhead"),
    "minor": ("minor", "minor_head", "crime_head", "offence"),
    "status": ("status", "case_status"),
    "gravity": ("gravity", "case_gravity"),
    "station": ("station", "police_station", "ps_name"),
    "district": ("district", "district_name"),
    "date": ("date", "incident_date", "incidentfromdate"),
    "time": ("time", "incident_time", "incidentfromtime"),
    "location": ("location", "place_of_occurrence", "occurrence_place"),
    "lat": ("lat", "latitude"), "lng": ("lng", "longitude"),
    "officer": ("officer", "investigating_officer", "io_name"),
    "complainant": ("complainant", "complainant_name"),
    "victim": ("victim", "victim_name"), "brief": ("brief", "brief_facts", "narrative"),
    "accused": ("accused", "accused_names"), "acts": ("acts", "sections", "act_sections"),
}


def mapped_value(record, field, default=""):
    normalized = {re.sub(r"[^a-z0-9]", "", str(key).lower()): value for key, value in record.items()}
    for alias in CCTNS_FIELD_ALIASES[field]:
        key = re.sub(r"[^a-z0-9]", "", alias.lower())
        if key in normalized and normalized[key] not in {None, ""}:
            return normalized[key]
    return default


def explainable_risk(case, db):
    """Transparent baseline; intended for validation, never as an automated enforcement decision."""
    accused_counts = []
    for name in case.get("accused", []):
        if is_placeholder_identity(name):
            continue
        accused_counts.append(db.execute("SELECT COUNT(*) FROM case_accused ca JOIN accused a ON a.id=ca.accused_id WHERE a.identity_key=?", (normalize_person_name(name).replace(" ", ""),)).fetchone()[0])
    nearby = 0
    if case.get("lat") is not None and case.get("lng") is not None:
        for row in db.execute("SELECT latitude,longitude FROM cases WHERE latitude IS NOT NULL AND longitude IS NOT NULL"):
            nearby += int(distance_km(float(case["lat"]), float(case["lng"]), row[0], row[1]) <= 5)
    features = {"heinous": int(str(case.get("gravity", "")).lower() == "heinous"), "repeat_identity_max": max(accused_counts, default=0), "nearby_cases_5km": nearby, "night_time": int(str(case.get("time", "12:00"))[:2].isdigit() and (int(str(case.get("time"))[:2]) >= 22 or int(str(case.get("time"))[:2]) < 5))}
    contributions = {"gravity": features["heinous"] * 25, "repeat identity": min(features["repeat_identity_max"] * 12, 30), "5 km density": min(features["nearby_cases_5km"] * 4, 25), "night-time pattern": features["night_time"] * 15}
    score = max(0, min(100, 15 + sum(contributions.values())))
    return score, features, contributions


def import_cctns_records(records, source_name, officer_id):
    accepted, errors, imported_ids = 0, [], []
    with get_db() as db:
        for index, raw in enumerate(records, 2):
            try:
                crime_no = str(mapped_value(raw, "crime_no")).strip()
                station, district = str(mapped_value(raw, "station")).strip(), str(mapped_value(raw, "district")).strip()
                date, location = normalized_form_date(mapped_value(raw, "date")), str(mapped_value(raw, "location")).strip()
                if not all((crime_no, station, district, date, location)):
                    raise ValueError("missing crime_no, station, district, date or location")
                existing = db.execute("SELECT id FROM cases WHERE crime_no=?", (crime_no,)).fetchone()
                case_id = existing[0] if existing else int(re.sub(r"\D", "", str(mapped_value(raw, "case_no", crime_no)))[-9:] or 0)
                while not existing and db.execute("SELECT 1 FROM cases WHERE id=?", (case_id,)).fetchone():
                    case_id += 1
                split_values = lambda value: [part.strip() for part in re.split(r"[|;,]", str(value)) if part.strip()]
                case = {"id": case_id, "crime_no": crime_no, "case_no": str(mapped_value(raw, "case_no", crime_no[-9:])), "title": str(mapped_value(raw, "title", "Imported FIR")), "category": "FIR", "major": str(mapped_value(raw, "major", "Other")), "minor": str(mapped_value(raw, "minor", "Other")), "status": str(mapped_value(raw, "status", "Under Investigation")), "gravity": str(mapped_value(raw, "gravity", "Non-Heinous")), "station": station, "district": district, "date": date, "time": normalized_form_time(mapped_value(raw, "time", "00:00")), "location": location, "lat": float(mapped_value(raw, "lat")) if mapped_value(raw, "lat") not in {"", None} else None, "lng": float(mapped_value(raw, "lng")) if mapped_value(raw, "lng") not in {"", None} else None, "officer": str(mapped_value(raw, "officer", officer_id)), "complainant": str(mapped_value(raw, "complainant")), "victim": str(mapped_value(raw, "victim")), "brief": str(mapped_value(raw, "brief")), "accused": split_values(mapped_value(raw, "accused")), "acts": split_values(mapped_value(raw, "acts"))}
                score, features, explanation = explainable_risk(case, db)
                db.execute("""INSERT OR REPLACE INTO cases(id,crime_no,case_no,title,category,major_head,minor_head,status,gravity,station,district,incident_date,incident_time,location,latitude,longitude,officer,complainant,victim,brief_facts,risk_score,source_language,source_document) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""", (case["id"],case["crime_no"],case["case_no"],case["title"],case["category"],case["major"],case["minor"],case["status"],case["gravity"],case["station"],case["district"],case["date"],case["time"],case["location"],case["lat"],case["lng"],case["officer"],case["complainant"],case["victim"],case["brief"],score,detect_language(case["brief"]),source_name))
                db.execute("DELETE FROM case_accused WHERE case_id=?", (case_id,)); db.execute("DELETE FROM case_acts WHERE case_id=?", (case_id,))
                for order, name in enumerate(case["accused"], 1):
                    accused_id, _, _ = resolve_accused(db, name); db.execute("INSERT OR IGNORE INTO case_accused VALUES (?,?,?)", (case_id, accused_id, order))
                db.executemany("INSERT OR IGNORE INTO case_acts VALUES (?,?)", [(case_id, act) for act in case["acts"]])
                db.execute("INSERT INTO model_predictions(case_id,model_version,score,features_json,explanation_json,created_at) VALUES (?,?,?,?,?,?)", (case_id,"transparent-baseline-1",score,json.dumps(features),json.dumps(explanation),datetime.now().isoformat()))
                accepted += 1; imported_ids.append(case_id)
            except (ValueError, TypeError, sqlite3.Error) as exc:
                errors.append({"row": index, "error": str(exc)})
    return accepted, errors, imported_ids


def all_case_records():
    with get_db() as db:
        return [case_from_row(row, db) for row in db.execute("SELECT * FROM cases ORDER BY incident_date DESC").fetchall()]


def quickml_audit(action, resource, detail):
    audit(action, resource, detail)


def grounded_ai_answer(question, case, linked, history):
    """Use only Catalyst QuickML; return None for the deterministic safe fallback."""
    result = CatalystQuickMLEngine().answer(
        question, all_case_records(), current_user(), base_case_id=case["id"],
        history=[{"role": item["role"], "content": item["content"]} for item in history[-6:]],
        audit_callback=quickml_audit,
    )
    if not result:
        return None
    evidence = []
    for item in result["evidence"]:
        evidence.append({
            "table": "QuickMLRAG", "field": "RetrievedRecord",
            "value": f"{item.get('title') or item.get('offence')} · {item.get('location')} · {item.get('date')}",
            "record": item["evidence_id"],
        })
    return {**result, "evidence": evidence}


@app.context_processor
def inject_globals():
    page_user = None if request.endpoint == "login" and catalyst_auth_enabled() else current_user()
    return {"user": page_user, "current_year": datetime.now().year, "csrf_token": csrf_token()}


@app.route("/", methods=["GET", "POST"])
def login():
    if catalyst_auth_enabled():
        return render_template("login.html", error=None, catalyst_auth=True)
    if current_user() and request.method == "GET":
        return redirect(url_for("workspace"))
    error = None
    if request.method == "POST":
        officer_id = request.form.get("officer_id", "").strip().upper()
        password = request.form.get("password", "")
        with get_db() as db:
            account = db.execute("SELECT * FROM users WHERE officer_id=? AND active=1", (officer_id,)).fetchone()
        if account and check_password_hash(account["password_hash"], password):
            session.clear()
            session["officer_id"] = officer_id
            session["csrf_token"] = secrets.token_urlsafe(32)
            session.permanent = True
            audit("LOGIN", "AUTH", "Successful demo login")
            return redirect(url_for("workspace"))
        error = "Officer ID or password is incorrect."
    return render_template("login.html", error=error, catalyst_auth=False)


@app.route("/logout")
def logout():
    audit("LOGOUT", "AUTH")
    session.clear()
    if catalyst_auth_enabled():
        return render_template("catalyst_logout.html", login_url=url_for("login", _external=True, _scheme="https"))
    return redirect(url_for("login"))


@app.route("/workspace")
@login_required
def workspace():
    user = current_user()
    if user["role"] in {"supervisor", "policymaker"}:
        return redirect(url_for("dashboard"))
    return redirect(url_for("cases"))


@app.route("/cases")
@login_required
def cases():
    query = request.args.get("q", "").strip().lower()
    with get_db() as db:
        if query:
            pattern = f"%{query}%"
            rows = db.execute("""SELECT DISTINCT c.* FROM cases c LEFT JOIN case_accused ca ON ca.case_id=c.id LEFT JOIN accused a ON a.id=ca.accused_id
                WHERE lower(c.crime_no) LIKE ? OR lower(c.case_no) LIKE ? OR lower(c.title) LIKE ? OR lower(c.location) LIKE ? OR lower(c.minor_head) LIKE ? OR lower(a.canonical_name) LIKE ?
                ORDER BY c.incident_date DESC""", (pattern,)*6).fetchall()
            audit("SEARCH", "CASE_INDEX", query)
        else:
            rows = db.execute("SELECT * FROM cases ORDER BY incident_date DESC").fetchall()
        filtered = [case_from_row(row, db) for row in rows]
    return render_template("cases.html", cases=filtered, query=query)


@app.route("/fir/new", methods=["GET", "POST"])
@roles_required("investigator", "analyst")
def new_fir():
    error = None
    extracted_text = ""
    detected_language = ""
    if request.method == "POST":
        try:
            source_upload = request.files.get("fir_document")
            extracted_text, source_document = extract_document(source_upload)
            cloud_file_id = cloud_upload(source_upload, source_document) if source_document else None
            source_reference = f"{source_document} · Catalyst File ID {cloud_file_id}" if cloud_file_id else source_document
            narrative = request.form.get("brief_facts", "").strip() or extracted_text.strip()
            if not narrative:
                raise ValueError("Enter the FIR narrative or upload a document containing searchable text.")
            extraction = extract_fir_fields(narrative)
            def submitted(field, default=""):
                return request.form.get(field, "").strip() or extraction["fields"].get(field, default)
            required_fields = {
                "title": "Case title", "major": "Major crime head", "minor": "Minor crime head", "gravity": "Gravity",
                "station": "Police station", "district": "District", "incident_date": "Incident date",
                "incident_time": "Incident time", "location": "Location", "complainant": "Complainant",
                "acts": "Acts and sections",
            }
            missing = [label for field, label in required_fields.items() if not submitted(field)]
            if missing:
                raise ValueError("Complete the required fields: " + ", ".join(missing) + ".")
            detected_language = extraction["language"]
            with get_db() as db:
                next_id = db.execute("SELECT COALESCE(MAX(id),0)+1 FROM cases").fetchone()[0]
                case_no = submitted("case_no") or f"{datetime.now().year}{next_id:05d}"
                crime_no = submitted("crime_no") or f"1{443:04d}{6:04d}{datetime.now().year}{next_id:05d}"
                db.execute("""INSERT INTO cases(id,crime_no,case_no,title,category,major_head,minor_head,status,gravity,station,district,incident_date,incident_time,location,latitude,longitude,officer,complainant,victim,brief_facts,risk_score,source_language,source_document)
                    VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""", (
                    next_id, crime_no, case_no, submitted("title", "Untitled FIR"), "FIR",
                    submitted("major", "Other"), submitted("minor", "Other"), "Under Investigation",
                    submitted("gravity", "Non-Heinous"), submitted("station", current_user()["unit"]),
                    submitted("district", "Bengaluru Urban"), normalized_form_date(submitted("incident_date")) or datetime.now().strftime("%Y-%m-%d"),
                    normalized_form_time(submitted("incident_time")) or datetime.now().strftime("%H:%M"), submitted("location", "Location pending verification"),
                    float(request.form.get("latitude") or 0), float(request.form.get("longitude") or 0), current_user()["name"],
                    submitted("complainant"), submitted("victim"), narrative,
                    int(request.form["risk_score"]) if request.form.get("risk_score", "").strip() else -1, detected_language, source_reference,
                ))
                for order, name in enumerate(filter(None, (part.strip() for part in submitted("accused").split(","))), 1):
                    accused_id, canonical_name, match_score = resolve_accused(db, name)
                    db.execute("INSERT INTO case_accused VALUES (?,?,?)", (next_id, accused_id, order))
                for act in filter(None, (part.strip() for part in submitted("acts").split(","))):
                    db.execute("INSERT INTO case_acts VALUES (?,?)", (next_id, act))
                db.execute("""INSERT INTO fir_extractions(case_id,source_document,source_language,extraction_confidence,missing_fields,verified_by,created_at)
                    VALUES (?,?,?,?,?,?,?)""", (next_id, source_reference, detected_language, extraction["confidence"], ",".join(extraction["missing"]), current_user()["id"], datetime.now().isoformat(timespec="seconds")))
            persist_case_to_cloud(next_id)
            cloud_upsert("FIRExtractions", crime_no, {"case_id": next_id, "source_document": source_reference, "source_language": detected_language, "confidence": extraction["confidence"], "missing": extraction["missing"], "verified_by": current_user()["id"]})
            audit("CREATE", "FIR", f"{crime_no} · {detected_language} · {source_reference or 'manual entry'}")
            return redirect(url_for("case_board", case_id=next_id))
        except (ValueError, sqlite3.IntegrityError) as exc:
            error = str(exc)
    return render_template("fir_form.html", error=error, extracted_text=extracted_text, detected_language=detected_language)


@app.post("/api/fir/extract")
@roles_required("investigator", "analyst")
def preview_fir_extraction():
    try:
        text, filename = extract_document(request.files.get("fir_document"))
        text = request.form.get("brief_facts", "").strip() or text
        if not text.strip():
            return jsonify({"error": "Upload a searchable PDF/TXT file or enter an FIR narrative."}), 400
        result = extract_fir_fields(text)
        result.update({"source_document": filename, "text": text})
        audit("EXTRACT_PREVIEW", "FIR", f"{filename or 'narrative'} · {result['language']} · {result['confidence']}%")
        return jsonify(result)
    except (ValueError, OSError) as exc:
        return jsonify({"error": str(exc)}), 400


@app.post("/api/admin/import-cctns")
@roles_required("analyst", "supervisor")
def import_cctns():
    upload = request.files.get("dataset")
    if not upload or not upload.filename:
        return jsonify({"error": "Attach a UTF-8 CSV or JSON dataset."}), 400
    raw = upload.read()
    if len(raw) > 20 * 1024 * 1024:
        return jsonify({"error": "Dataset exceeds the 20 MB controlled-import limit."}), 413
    checksum = hashlib.sha256(raw).hexdigest()
    with get_db() as db:
        previous = db.execute("SELECT * FROM import_jobs WHERE checksum=?", (checksum,)).fetchone()
    if previous:
        return jsonify({"error": "This exact dataset was already imported.", "import_job": dict(previous)}), 409
    try:
        decoded = raw.decode("utf-8-sig")
        records = json.loads(decoded) if upload.filename.lower().endswith(".json") else list(csv.DictReader(decoded.splitlines()))
        if isinstance(records, dict):
            records = records.get("records") or records.get("cases") or []
        if not isinstance(records, list) or not records:
            raise ValueError("No records were found in the dataset")
        accepted, errors, imported_ids = import_cctns_records(records, upload.filename, current_user()["id"])
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        return jsonify({"error": str(exc)}), 400
    with get_db() as db:
        db.execute("INSERT INTO import_jobs(checksum,source_name,imported_by,accepted,rejected,errors_json,created_at) VALUES (?,?,?,?,?,?,?)", (checksum,upload.filename,current_user()["id"],accepted,len(errors),json.dumps(errors),datetime.now().isoformat()))
    for case_id in imported_ids:
        try:
            persist_case_to_cloud(case_id)
        except Exception:
            app.logger.exception("Cloud persistence failed for imported case %s", case_id)
    audit("BULK_IMPORT", "CCTNS", f"{upload.filename} · accepted={accepted} · rejected={len(errors)} · sha256={checksum}")
    return jsonify({"accepted": accepted, "rejected": len(errors), "errors": errors[:100], "checksum": checksum}), 201 if accepted else 422


@app.get("/api/admin/permissions")
@login_required
def permission_matrix():
    matrix = {
        "investigator": ["cases:read", "fir:create", "intelligence:query", "graph:explore", "conversation:export"],
        "analyst": ["cases:read", "fir:create", "dataset:import", "intelligence:query", "graph:explore", "conversation:export", "audit:read", "metrics:read"],
        "supervisor": ["cases:read", "intelligence:query", "graph:explore", "conversation:export", "audit:read", "metrics:read", "backup:export", "retention:execute"],
        "policymaker": ["aggregate-dashboard:read"],
    }
    return jsonify({"role": current_user()["role"], "permissions": matrix[current_user()["role"]], "matrix": matrix if current_user()["role"] == "supervisor" else None})


@app.get("/api/admin/backup")
@roles_required("supervisor")
def export_backup():
    snapshot = BytesIO()
    with get_db() as source:
        temporary = NamedTemporaryFile(suffix=".db", delete=False)
        temporary.close()
        destination = sqlite3.connect(temporary.name)
        source.backup(destination); destination.close()
        snapshot.write(Path(temporary.name).read_bytes()); Path(temporary.name).unlink(missing_ok=True)
    snapshot.seek(0)
    audit("BACKUP_EXPORT", "DATABASE", "Encrypted transport required; store only in approved KSP vault")
    return send_file(snapshot, mimetype="application/vnd.sqlite3", as_attachment=True, download_name=f"crimegpt-backup-{datetime.now().strftime('%Y%m%d-%H%M')}.db")


@app.post("/api/admin/retention")
@roles_required("supervisor")
def enforce_retention():
    days = max(30, min(int((request.get_json(silent=True) or {}).get("conversation_days", 365)), 3650))
    with get_db() as db:
        deleted = db.execute("DELETE FROM conversation_messages WHERE created_at < datetime('now', ?)", (f"-{days} days",)).rowcount
    audit("RETENTION_EXECUTED", "CONVERSATIONS", f"days={days} · deleted={deleted}")
    return jsonify({"retention_days": days, "deleted_messages": deleted})


@app.get("/api/model/evaluation")
@roles_required("analyst", "supervisor")
def model_evaluation():
    with get_db() as db:
        rows = db.execute("SELECT score,outcome FROM model_predictions WHERE outcome IS NOT NULL").fetchall()
    if not rows:
        return jsonify({"status": "not-validated", "message": "No investigator-confirmed outcomes are available. The baseline must not be described as predictive or used for enforcement.", "minimum_recommended_labels": 500}), 200
    labels = [(int(row[0]) >= 70, bool(row[1])) for row in rows]
    tp=sum(p and y for p,y in labels); fp=sum(p and not y for p,y in labels); tn=sum(not p and not y for p,y in labels); fn=sum(not p and y for p,y in labels)
    safe_div=lambda a,b: round(a/b,4) if b else None
    return jsonify({"status":"evaluation-only","labels":len(labels),"threshold":70,"precision":safe_div(tp,tp+fp),"recall":safe_div(tp,tp+fn),"false_positive_rate":safe_div(fp,fp+tn),"confusion_matrix":{"tp":tp,"fp":fp,"tn":tn,"fn":fn}})


@app.route("/dashboard")
@login_required
def dashboard():
    audit("VIEW", "AGGREGATE_DASHBOARD")
    with get_db() as db:
        stats = dict(db.execute("SELECT COUNT(*) total, SUM(status='Under Investigation') active, ROUND(AVG(CASE WHEN risk_score>=0 THEN risk_score END),1) avg_risk, SUM(gravity='Heinous') heinous FROM cases").fetchone())
        stats["linked"] = db.execute("SELECT COUNT(*) FROM accused WHERE (SELECT COUNT(*) FROM case_accused WHERE accused_id=accused.id)>1").fetchone()[0]
        rows = db.execute("SELECT incident_date, location, district, minor_head, risk_score FROM cases").fetchall()
        hotspots = [dict(row) for row in db.execute("SELECT location, district, COUNT(*) case_count, ROUND(AVG(CASE WHEN risk_score>=0 THEN risk_score END),0) risk FROM cases GROUP BY lower(location), lower(district) ORDER BY case_count DESC, risk DESC LIMIT 5")]
        repeat = [dict(row) for row in db.execute("SELECT a.canonical_name name, COUNT(*) case_count FROM accused a JOIN case_accused ca ON ca.accused_id=a.id GROUP BY a.id HAVING COUNT(*)>1 ORDER BY case_count DESC LIMIT 4")]
    monthly = {}
    for row in rows:
        try:
            date = datetime.strptime(row["incident_date"], "%d %b %Y")
        except ValueError:
            continue
        key = date.strftime("%Y-%m")
        monthly[key] = monthly.get(key, 0) + 1
    trend = [{"label": datetime.strptime(key, "%Y-%m").strftime("%b %y"), "count": count} for key, count in sorted(monthly.items())[-6:]]
    maximum = max((item["count"] for item in trend), default=1)
    for item in trend:
        item["height"] = max(14, round(item["count"] / maximum * 100))
    alerts = []
    for item in hotspots[:2]:
        risk_detail = f"average assessed risk {int(item['risk'])}/100" if item["risk"] is not None else "risk not yet assessed"
        alerts.append({"title": f"Hotspot signal · {item['location']}", "detail": f"{item['case_count']} recorded FIR(s), {risk_detail}. Review patrol coverage and recent link evidence."})
    for item in repeat[:2]:
        alerts.append({"title": f"Repeat-identity signal · {item['name']}", "detail": f"Appears in {item['case_count']} FIRs. This is an analytical lead; identity requires investigator verification."})
    return render_template("dashboard.html", stats=stats, trend=trend, hotspots=hotspots, alerts=alerts)


@app.route("/case/<int:case_id>")
@login_required
def case_board(case_id):
    if current_user()["role"] == "policymaker":
        return redirect(url_for("dashboard"))
    case = find_case(case_id)
    if not case:
        return "Case not found", 404
    audit("VIEW", "CASE", case["crime_no"])
    linked = linked_cases(case_id)
    conversation = active_conversation(case_id)
    history = conversation_history(conversation["id"]) if conversation else []
    return render_template("board.html", case=case, board=board_payload(case), linked=linked, conversation=conversation, conversation_history=history)


@app.post("/api/case/<int:case_id>/ask")
@roles_required("investigator", "analyst", "supervisor")
def ask_case(case_id):
    case = find_case(case_id)
    if not case:
        return jsonify({"error": "Case not found"}), 404
    question = (request.get_json(silent=True) or {}).get("question", "").strip()
    if not question:
        return jsonify({"error": "Question is required"}), 400
    conversation = active_conversation(case_id)
    history = conversation_history(conversation["id"])
    previous_user_question = next((item["content"] for item in reversed(history) if item["role"] == "user"), "")
    question_language = detect_language(question)
    store_message(conversation["id"], "user", question, question_language)
    normalized = question.lower()
    english_context_reference = re.search(r"\b(?:his|her|their|that|those|it)\b", normalized)
    kannada_context_reference = any(term in normalized for term in ["ಅವನ", "ಅದರ", "ಅವು"])
    context_text = f"{previous_user_question} {question}".lower() if english_context_reference or kannada_context_reference else normalized
    linked = linked_cases(case_id)
    ai_result = grounded_ai_answer(question, case, linked, history)
    engine = ai_result.get("engine", "catalyst-quickml") if ai_result else "deterministic-evidence-engine"
    if ai_result:
        answer, evidence, confidence, kind = ai_result["answer"], ai_result["evidence"], ai_result["confidence"], ai_result["kind"]
    elif any(term in normalized for term in ["where", "when", "location", "place", "ಎಲ್ಲಿ", "ಯಾವಾಗ"]):
        answer = f"The incident was recorded at {case['location']} on {case['date']} at {case['time']}."
        evidence = [{"table": "CaseMaster", "field": "Location", "value": case["location"], "record": case["crime_no"]}, {"table": "CaseMaster", "field": "IncidentFromDate", "value": f"{case['date']} {case['time']}", "record": case["crime_no"]}]
        confidence, kind = 100, "Verified fact"
    elif any(term in context_text for term in ["other case", "repeat", "linked", "history", "ಹಿಂದಿನ"]):
        if linked:
            names = ", ".join(f"FIR {item['case_no']} ({item['link_score']}% link score)" for item in linked[:4])
            answer = f"Explainable cross-case leads found: {names}. Scores combine accused-name similarity, crime sub-head, distance and time window; identity must still be confirmed by an investigator."
            evidence = [{**entry, "record": f"FIR {item['case_no']} · {'; '.join(item['link_reasons'])}"} for item in linked[:4] for entry in item["link_evidence"]]
            confidence = linked[0]["link_score"]
            kind = "Analytical lead"
        else:
            answer, evidence, confidence, kind = "No linked case was found in the current authorised dataset.", [{"table": "Accused", "field": "CaseMasterID", "value": str(case_id), "record": "Current case"}], 100, "Verified fact"
    elif any(term in context_text for term in ["section", "act", "charge", "ಕಲಂ"]):
        answer = "Recorded legal provisions: " + ", ".join(case["acts"]) + "."
        evidence = [{"table": "ActSectionAssociation", "field": "ActID / SectionID", "value": act, "record": case["crime_no"]} for act in case["acts"]]
        confidence, kind = 100, "Verified fact"
    else:
        answer = f"FIR {case['case_no']} concerns {case['minor'].lower()} at {case['location']}. It is {case['status'].lower()} and lists {len(case['accused'])} accused record(s). Ask about linked cases, location, or legal sections for a sourced answer."
        evidence = [{"table": "CaseMaster", "field": "BriefFacts", "value": case["brief"], "record": case["crime_no"]}, {"table": "CaseStatusMaster", "field": "CaseStatusName", "value": case["status"], "record": case["crime_no"]}]
        confidence, kind = 100, "Verified fact"
    audit("AI_QUERY", "CASE", f"{case['crime_no']} · {question[:80]}")
    store_message(conversation["id"], "assistant", answer, question_language, kind, confidence, evidence)
    return jsonify({"answer": answer, "evidence": evidence, "confidence": confidence, "kind": kind, "engine": engine, "conversation_id": conversation["id"], "context_used": bool(previous_user_question and context_text != normalized), "linked_cases": [{"id": item["id"], "case_no": item["case_no"], "minor": item["minor"], "score": item["link_score"], "reasons": item["link_reasons"]} for item in linked]})


@app.post("/api/analytics/ask")
@roles_required("investigator", "analyst", "supervisor", "policymaker")
def ask_analytics():
    """Cross-case natural-language analytics through role-scoped QuickML retrieval."""
    question = (request.get_json(silent=True) or {}).get("question", "").strip()
    if not question:
        return jsonify({"error": "Question is required"}), 400
    result = CatalystQuickMLEngine().answer(
        question, all_case_records(), current_user(), audit_callback=quickml_audit,
    )
    if not result:
        return jsonify({
            "error": "Catalyst QuickML LLM Serving is not configured or returned an ungrounded response.",
            "intent": classify_query(question), "engine": "unavailable",
        }), 503
    audit("AI_ANALYTICS", "AUTHORISED_CASE_SCOPE", f"intent={result['intent']} evidence={','.join(result['evidence_ids'])}")
    return jsonify(result)


@app.get("/api/case/<int:case_id>/risk-explanation")
@roles_required("investigator", "analyst", "supervisor")
def risk_explanation(case_id):
    """Keep the stored score locked; QuickML only phrases active-factor evidence."""
    case = find_case(case_id)
    if not case:
        return jsonify({"error": "Case not found"}), 404
    if int(case.get("risk", -1)) < 0:
        result = CatalystQuickMLEngine().explain_risk(case, {}, {}, current_user(), quickml_audit)
        return jsonify(result)
    with get_db() as db:
        _score, _features, contributions = explainable_risk(case, db)
    active = {name: points for name, points in contributions.items() if points > 0}
    evidence_rows = {name: [case["crime_no"]] for name in active}
    result = CatalystQuickMLEngine().explain_risk(case, active, evidence_rows, current_user(), quickml_audit)
    audit("RISK_EXPLANATION", "CASE", f"{case['crime_no']} engine={result['engine']}")
    return jsonify(result)


@app.post("/api/case/<int:case_id>/expand")
@roles_required("investigator", "analyst", "supervisor")
def expand_graph(case_id):
    source_case = find_case(case_id)
    if not source_case:
        return jsonify({"error": "Case not found"}), 404
    payload = request.get_json(silent=True) or {}
    node_type = payload.get("type", "")
    value = str(payload.get("value", "")).strip()
    matches = []
    with get_db() as db:
        if node_type == "location":
            rows = db.execute("SELECT * FROM cases WHERE id<>? AND latitude IS NOT NULL AND longitude IS NOT NULL", (case_id,)).fetchall()
            for row in rows:
                candidate = case_from_row(row, db)
                distance = distance_km(source_case["lat"], source_case["lng"], candidate["lat"], candidate["lng"])
                if distance <= 5:
                    matches.append((candidate, f"{distance:.1f} km away", max(55, round(100 - distance * 8))))
        elif node_type == "accused":
            rows = db.execute("""SELECT DISTINCT c.* FROM cases c JOIN case_accused ca ON ca.case_id=c.id
                JOIN accused a ON a.id=ca.accused_id WHERE c.id<>? AND lower(a.canonical_name)=lower(?)""", (case_id, value)).fetchall()
            matches = [(case_from_row(row, db), f"Same accused · {value}", 100) for row in rows]
        elif node_type == "offence":
            rows = db.execute("SELECT * FROM cases WHERE id<>? AND lower(minor_head)=lower(?)", (case_id, value)).fetchall()
            matches = [(case_from_row(row, db), f"Same offence · {value}", 90) for row in rows]
        elif node_type == "victim":
            rows = db.execute("SELECT * FROM cases WHERE id<>? AND (lower(victim)=lower(?) OR lower(complainant)=lower(?))", (case_id, value, value)).fetchall()
            matches = [(case_from_row(row, db), f"Same person · {value}", 100) for row in rows]
    matches.sort(key=lambda item: item[2], reverse=True)
    audit("EXPAND_GRAPH", "CASE", f"{source_case['crime_no']} · {node_type} · {value}")
    return jsonify({"source_type": node_type, "count": len(matches), "cases": [{
        "id": item[0]["id"], "case_no": item[0]["case_no"], "title": item[0]["title"], "minor": item[0]["minor"],
        "date": item[0]["date"], "time": item[0]["time"], "location": item[0]["location"], "reason": item[1], "confidence": item[2],
        "url": url_for("case_board", case_id=item[0]["id"]),
    } for item in matches[:8]]})


@app.get("/case/<int:case_id>/conversation.pdf")
@login_required
def export_conversation_pdf(case_id):
    case = find_case(case_id)
    if not case or current_user()["role"] == "policymaker":
        return "Case not found", 404
    conversation = active_conversation(case_id, create=False)
    history = conversation_history(conversation["id"]) if conversation else []
    try:
        from reportlab.lib import colors
        from reportlab.lib.enums import TA_CENTER
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
        from reportlab.lib.units import mm
        from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
    except ImportError:
        return "PDF support is not installed", 503
    buffer = BytesIO()
    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(name="ReportTitle", parent=styles["Title"], textColor=colors.HexColor("#0b2948"), fontSize=20, leading=24, alignment=TA_CENTER))
    styles.add(ParagraphStyle(name="Meta", parent=styles["Normal"], textColor=colors.HexColor("#607387"), fontSize=8, leading=12))
    styles.add(ParagraphStyle(name="UserTurn", parent=styles["Normal"], backColor=colors.HexColor("#edf6fb"), borderColor=colors.HexColor("#c7dfec"), borderWidth=.5, borderPadding=8, fontSize=9, leading=14, spaceAfter=7))
    styles.add(ParagraphStyle(name="AssistantTurn", parent=styles["Normal"], backColor=colors.HexColor("#f8fafc"), borderColor=colors.HexColor("#dce4eb"), borderWidth=.5, borderPadding=8, fontSize=9, leading=14, spaceAfter=7))
    doc = SimpleDocTemplate(buffer, pagesize=A4, rightMargin=18*mm, leftMargin=18*mm, topMargin=16*mm, bottomMargin=16*mm, title=f"FIR {case['case_no']} Intelligence Conversation")
    story = [Paragraph("KSP Crime Intelligence", styles["ReportTitle"]), Spacer(1, 4*mm), Table([
        ["FIR", case["case_no"], "Crime No.", case["crime_no"]],
        ["Case", case["title"], "Status", case["status"]],
        ["Location", case["location"], "Officer", current_user()["name"]],
    ], colWidths=[22*mm, 58*mm, 25*mm, 60*mm], style=TableStyle([("BACKGROUND",(0,0),(0,-1),colors.HexColor("#edf4f8")),("BACKGROUND",(2,0),(2,-1),colors.HexColor("#edf4f8")),("GRID",(0,0),(-1,-1),.35,colors.HexColor("#d6e1e9")),("FONTNAME",(0,0),(-1,-1),"Helvetica"),("FONTSIZE",(0,0),(-1,-1),7.5),("VALIGN",(0,0),(-1,-1),"TOP"),("PADDING",(0,0),(-1,-1),6)])), Spacer(1, 6*mm)]
    if not history:
        story.append(Paragraph("No conversation has been recorded for this case.", styles["Meta"]))
    for index, message in enumerate(history, 1):
        label = "Investigator" if message["role"] == "user" else f"Intelligence agent · {message.get('kind') or 'Response'} · confidence {message.get('confidence') or '-'}%"
        story.append(Paragraph(f"<b>{escape(label)}</b><br/>{escape(message['content'])}", styles["UserTurn" if message["role"] == "user" else "AssistantTurn"]))
        if message["role"] == "assistant" and message["evidence"]:
            evidence_rows = [["Source", "Value", "Record"]] + [[f"{item.get('table','')}.{item.get('field','')}", item.get("value", ""), item.get("record", "")] for item in message["evidence"]]
            story.append(Table(evidence_rows, repeatRows=1, colWidths=[42*mm, 58*mm, 66*mm], style=TableStyle([("BACKGROUND",(0,0),(-1,0),colors.HexColor("#123b62")),("TEXTCOLOR",(0,0),(-1,0),colors.white),("GRID",(0,0),(-1,-1),.3,colors.HexColor("#d9e2e9")),("FONTSIZE",(0,0),(-1,-1),6.5),("VALIGN",(0,0),(-1,-1),"TOP"),("PADDING",(0,0),(-1,-1),4)])))
            story.append(Spacer(1, 3*mm))
    story.extend([Spacer(1, 5*mm), Paragraph(f"Generated {datetime.now().strftime('%d %b %Y %H:%M')} · Authorised use only · Every analytical lead requires investigator verification.", styles["Meta"])])
    doc.build(story)
    buffer.seek(0)
    audit("EXPORT_PDF", "CONVERSATION", case["crime_no"])
    return send_file(buffer, mimetype="application/pdf", as_attachment=True, download_name=f"FIR-{case['case_no']}-conversation.pdf")


@app.get("/api/audit")
@roles_required("supervisor", "analyst")
def audit_feed():
    with get_db() as db:
        rows = db.execute("SELECT * FROM audit_log ORDER BY id DESC LIMIT 50").fetchall()
    return jsonify([dict(row) for row in rows])


init_db()


if __name__ == "__main__":
    port = int(os.environ.get("PORT", os.environ.get("X_ZOHO_CATALYST_LISTEN_PORT", "5000")))
    app.run(host="0.0.0.0", port=port, debug=os.environ.get("FLASK_DEBUG") == "1")
