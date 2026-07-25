from datetime import datetime
from functools import wraps
from pathlib import Path
import sqlite3
import re
import unicodedata
from difflib import SequenceMatcher
from math import asin, cos, radians, sin, sqrt
from flask import Flask, jsonify, redirect, render_template, request, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash
from pypdf import PdfReader


app = Flask(__name__)
app.secret_key = "dev-only-change-before-deployment"
app.config["MAX_CONTENT_LENGTH"] = 5 * 1024 * 1024
DB_PATH = Path(__file__).with_name("ksp_intelligence.db")


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


def get_db():
    connection = sqlite3.connect(DB_PATH)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    return connection


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
        """)
        if db.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 0:
            db.executemany(
                "INSERT INTO users VALUES (?, ?, ?, ?, ?, ?, 1)",
                [(officer_id, generate_password_hash(item["password"], method="pbkdf2:sha256"), item["name"], item["role"], item["rank"], item["unit"]) for officer_id, item in USERS.items()],
            )
        if db.execute("SELECT COUNT(*) FROM cases").fetchone()[0] == 0:
            for case in CASES:
                db.execute("""INSERT INTO cases VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""", (
                    case["id"], case["crime_no"], case["case_no"], case["title"], case["category"], case["major"], case["minor"],
                    case["status"], case["gravity"], case["station"], case["district"], case["date"], case["time"], case["location"],
                    case["lat"], case["lng"], case["officer"], case["complainant"], case["victim"], case["brief"], case["risk"],
                ))
                for order, name in enumerate(case["accused"], 1):
                    identity_key = "".join(character for character in name.lower() if character.isalnum())
                    db.execute("INSERT OR IGNORE INTO accused(canonical_name, identity_key) VALUES (?, ?)", (name, identity_key))
                    accused_id = db.execute("SELECT id FROM accused WHERE identity_key = ?", (identity_key,)).fetchone()[0]
                    db.execute("INSERT INTO case_accused VALUES (?, ?, ?)", (case["id"], accused_id, order))
                db.executemany("INSERT INTO case_acts VALUES (?, ?)", [(case["id"], act) for act in case["acts"]])
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
    data["accused"] = [item[0] for item in db.execute("SELECT a.canonical_name FROM accused a JOIN case_accused ca ON ca.accused_id=a.id WHERE ca.case_id=? ORDER BY ca.person_order", (data["id"],))]
    data["acts"] = [item[0] for item in db.execute("SELECT act_section FROM case_acts WHERE case_id=? ORDER BY act_section", (data["id"],))]
    if owns_connection:
        db.close()
    return data


def current_user():
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


def audit(action, resource, detail=""):
    user = current_user()
    if user:
        with get_db() as db:
            db.execute("INSERT INTO audit_log(occurred_at,officer_id,role,action,resource,detail) VALUES (?,?,?,?,?,?)", (datetime.now().isoformat(timespec="seconds"), user["id"], user["role"], action, resource, detail))


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


def person_name_score(left, right):
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


@app.context_processor
def inject_globals():
    return {"user": current_user(), "current_year": datetime.now().year}


@app.route("/", methods=["GET", "POST"])
def login():
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
            audit("LOGIN", "AUTH", "Successful demo login")
            return redirect(url_for("workspace"))
        error = "Officer ID or password is incorrect."
    return render_template("login.html", error=error)


@app.route("/logout")
def logout():
    audit("LOGOUT", "AUTH")
    session.clear()
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
@login_required
def new_fir():
    if current_user()["role"] not in {"investigator", "analyst"}:
        return redirect(url_for("dashboard"))
    error = None
    extracted_text = ""
    detected_language = ""
    if request.method == "POST":
        try:
            extracted_text, source_document = extract_document(request.files.get("fir_document"))
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
                    int(request.form.get("risk_score") or 0), detected_language, source_document,
                ))
                for order, name in enumerate(filter(None, (part.strip() for part in submitted("accused").split(","))), 1):
                    accused_id, canonical_name, match_score = resolve_accused(db, name)
                    db.execute("INSERT INTO case_accused VALUES (?,?,?)", (next_id, accused_id, order))
                for act in filter(None, (part.strip() for part in submitted("acts").split(","))):
                    db.execute("INSERT INTO case_acts VALUES (?,?)", (next_id, act))
                db.execute("""INSERT INTO fir_extractions(case_id,source_document,source_language,extraction_confidence,missing_fields,verified_by,created_at)
                    VALUES (?,?,?,?,?,?,?)""", (next_id, source_document, detected_language, extraction["confidence"], ",".join(extraction["missing"]), current_user()["id"], datetime.now().isoformat(timespec="seconds")))
            audit("CREATE", "FIR", f"{crime_no} · {detected_language} · {source_document or 'manual entry'}")
            return redirect(url_for("case_board", case_id=next_id))
        except (ValueError, sqlite3.IntegrityError) as exc:
            error = str(exc)
    return render_template("fir_form.html", error=error, extracted_text=extracted_text, detected_language=detected_language)


@app.post("/api/fir/extract")
@login_required
def preview_fir_extraction():
    if current_user()["role"] not in {"investigator", "analyst"}:
        return jsonify({"error": "Forbidden"}), 403
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


@app.route("/dashboard")
@login_required
def dashboard():
    audit("VIEW", "AGGREGATE_DASHBOARD")
    with get_db() as db:
        stats = dict(db.execute("SELECT COUNT(*) total, SUM(status='Under Investigation') active, ROUND(AVG(risk_score),1) avg_risk, SUM(gravity='Heinous') heinous FROM cases").fetchone())
        stats["linked"] = db.execute("SELECT COUNT(*) FROM accused WHERE (SELECT COUNT(*) FROM case_accused WHERE accused_id=accused.id)>1").fetchone()[0]
    return render_template("dashboard.html", stats=stats)


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
    return render_template("board.html", case=case, board=board_payload(case), linked=linked)


@app.post("/api/case/<int:case_id>/ask")
@login_required
def ask_case(case_id):
    case = find_case(case_id)
    if not case:
        return jsonify({"error": "Case not found"}), 404
    question = (request.get_json(silent=True) or {}).get("question", "").strip()
    normalized = question.lower()
    linked = linked_cases(case_id)
    if any(term in normalized for term in ["other case", "repeat", "linked", "history", "ಹಿಂದಿನ"]):
        if linked:
            names = ", ".join(f"FIR {item['case_no']} ({item['link_score']}% link score)" for item in linked[:4])
            answer = f"Explainable cross-case leads found: {names}. Scores combine accused-name similarity, crime sub-head, distance and time window; identity must still be confirmed by an investigator."
            evidence = [{**entry, "record": f"FIR {item['case_no']} · {'; '.join(item['link_reasons'])}"} for item in linked[:4] for entry in item["link_evidence"]]
            confidence = linked[0]["link_score"]
            kind = "Analytical lead"
        else:
            answer, evidence, confidence, kind = "No linked case was found in the current authorised dataset.", [{"table": "Accused", "field": "CaseMasterID", "value": str(case_id), "record": "Current case"}], 100, "Verified fact"
    elif any(term in normalized for term in ["where", "location", "place", "ಎಲ್ಲಿ"]):
        answer = f"The incident was recorded at {case['location']} on {case['date']} at {case['time']}."
        evidence = [{"table": "CaseMaster", "field": "latitude / longitude", "value": f"{case['lat']}, {case['lng']}", "record": case["crime_no"]}, {"table": "CaseMaster", "field": "IncidentFromDate", "value": f"{case['date']} {case['time']}", "record": case["crime_no"]}]
        confidence, kind = 100, "Verified fact"
    elif any(term in normalized for term in ["section", "act", "charge", "ಕಲಂ"]):
        answer = "Recorded legal provisions: " + ", ".join(case["acts"]) + "."
        evidence = [{"table": "ActSectionAssociation", "field": "ActID / SectionID", "value": act, "record": case["crime_no"]} for act in case["acts"]]
        confidence, kind = 100, "Verified fact"
    else:
        answer = f"FIR {case['case_no']} concerns {case['minor'].lower()} at {case['location']}. It is {case['status'].lower()} and lists {len(case['accused'])} accused record(s). Ask about linked cases, location, or legal sections for a sourced answer."
        evidence = [{"table": "CaseMaster", "field": "BriefFacts", "value": case["brief"], "record": case["crime_no"]}, {"table": "CaseStatusMaster", "field": "CaseStatusName", "value": case["status"], "record": case["crime_no"]}]
        confidence, kind = 100, "Verified fact"
    audit("AI_QUERY", "CASE", f"{case['crime_no']} · {question[:80]}")
    return jsonify({"answer": answer, "evidence": evidence, "confidence": confidence, "kind": kind, "linked_cases": [{"id": item["id"], "case_no": item["case_no"], "minor": item["minor"], "score": item["link_score"], "reasons": item["link_reasons"]} for item in linked]})


@app.post("/api/case/<int:case_id>/expand")
@login_required
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


@app.get("/api/audit")
@login_required
def audit_feed():
    if current_user()["role"] not in {"supervisor", "analyst"}:
        return jsonify({"error": "Forbidden"}), 403
    with get_db() as db:
        rows = db.execute("SELECT * FROM audit_log ORDER BY id DESC LIMIT 50").fetchall()
    return jsonify([dict(row) for row in rows])


init_db()


if __name__ == "__main__":
    app.run(debug=True)
