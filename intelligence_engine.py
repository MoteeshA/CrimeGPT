"""Catalyst QuickML-backed, evidence-grounded intelligence services.

QuickML RAG is preferred. When RAG is not enabled for the Catalyst organisation,
the engine performs role-filtered retrieval locally and sends only those records to
the Catalyst-hosted LLM. It never calls an external model provider.
"""

from dataclasses import dataclass, field
from datetime import datetime, timedelta
import json
import os
import re
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


PLACEHOLDER_IDENTITY = re.compile(r"^(unknown|unidentified|not known|na|n/a|nil|suspect|accused)(\s+.*)?$", re.I)


def is_known_identity(value):
    value = re.sub(r"\s+", " ", str(value or "")).strip()
    return bool(value) and not PLACEHOLDER_IDENTITY.match(value)


def classify_query(question):
    text = str(question or "").lower()
    if any(term in text for term in ("compare", "versus", " vs ", "ಹೋಲಿಸಿ")):
        return "comparison"
    if any(term in text for term in ("changed", "change this month", "trend", "increase", "decrease", "ಬದಲಾವಣೆ")):
        return "trend"
    if any(term in text for term in ("accused", "network", "linked", "across", "ಆರೋಪಿ", "ಸಂಪರ್ಕ")):
        return "network"
    if any(term in text for term in ("within", "kilomet", "near", "where", "hotspot", "ಎಲ್ಲಿ")):
        return "spatial"
    return "case_fact"


def record_id(record):
    return str(record.get("crime_no") or record.get("case_no") or record.get("id"))


def scope_records(records, user, base_case_id=None):
    """Apply role scope before any record can reach RAG or LLM Serving."""
    role = str(user.get("role", "investigator")).lower()
    if role in {"analyst", "supervisor"}:
        scoped = list(records)
    elif role == "policymaker":
        # Policymakers receive aggregate-safe records without identity/narrative data.
        scoped = []
        for source in records:
            item = {key: source.get(key) for key in ("id", "crime_no", "case_no", "minor", "major", "date", "time", "district", "location", "gravity", "status", "risk")}
            item["accused"] = []
            item["brief"] = ""
            scoped.append(item)
    else:
        name = str(user.get("name", "")).casefold()
        unit = str(user.get("unit", "")).casefold()
        scoped = [r for r in records if (base_case_id is not None and str(r.get("id")) == str(base_case_id)) or str(r.get("officer", "")).casefold() == name or (unit and str(r.get("station", "")).casefold() == unit)]
    if base_case_id is not None and not any(str(r.get("id")) == str(base_case_id) for r in scoped):
        scoped.extend(r for r in records if str(r.get("id")) == str(base_case_id))
    return scoped


def _tokens(value):
    return set(re.findall(r"[\w]+", str(value or "").casefold(), re.UNICODE)) - {"the", "a", "an", "is", "in", "at", "of", "and", "this", "case", "show", "which", "what"}


def manual_retrieve(question, records, limit=12, base_case_id=None):
    query_tokens = _tokens(question)
    ranked = []
    for item in records:
        searchable = " ".join(str(item.get(key, "")) for key in ("crime_no", "case_no", "title", "major", "minor", "date", "time", "location", "district", "station", "brief"))
        searchable += " " + " ".join(name for name in item.get("accused", []) if is_known_identity(name))
        overlap = len(query_tokens & _tokens(searchable))
        score = overlap * 10 + (100 if base_case_id is not None and str(item.get("id")) == str(base_case_id) else 0)
        if overlap or score:
            ranked.append((score, item))
    ranked.sort(key=lambda pair: (pair[0], record_id(pair[1])), reverse=True)
    return [item for _, item in ranked[:limit]] or list(records)[:limit]


@dataclass
class QuickMLConfig:
    llm_endpoint: str = ""
    rag_endpoint: str = ""
    org_id: str = ""
    endpoint_key: str = ""
    access_token: str = ""
    rag_record_map: dict = field(default_factory=dict)
    timeout_seconds: int = 25

    @classmethod
    def from_env(cls):
        try:
            mapping = json.loads(os.environ.get("QUICKML_RAG_RECORD_DOCUMENT_MAP", "{}"))
        except json.JSONDecodeError:
            mapping = {}
        return cls(
            llm_endpoint=os.environ.get("QUICKML_LLM_ENDPOINT_URL", "").strip(),
            rag_endpoint=os.environ.get("QUICKML_RAG_ENDPOINT_URL", "").strip(),
            org_id=os.environ.get("QUICKML_ORG_ID", "").strip(),
            endpoint_key=os.environ.get("QUICKML_ENDPOINT_KEY", "").strip(),
            access_token=os.environ.get("QUICKML_OAUTH_ACCESS_TOKEN", "").strip(),
            rag_record_map=mapping,
            timeout_seconds=int(os.environ.get("QUICKML_TIMEOUT_SECONDS", "25")),
        )

    @property
    def llm_ready(self):
        # Catalyst GLM endpoints use OAuth + CATALYST-ORG. An endpoint key is
        # optional and is not issued by the current LLM Serving console flow.
        return all((self.llm_endpoint, self.org_id, self.access_token))

    @property
    def rag_ready(self):
        return self.llm_ready and bool(self.rag_endpoint and self.rag_record_map)


class CatalystQuickMLEngine:
    def __init__(self, config=None, transport=None):
        self.config = config or QuickMLConfig.from_env()
        self.transport = transport or self._http_post

    def _headers(self):
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Zoho-oauthtoken {self.config.access_token}",
            "CATALYST-ORG": self.config.org_id,
            "Environment": os.environ.get("CATALYST_ENVIRONMENT", "Development"),
        }
        if self.config.endpoint_key:
            headers["X-QUICKML-ENDPOINT-KEY"] = self.config.endpoint_key
        return headers

    def _http_post(self, url, payload):
        request = Request(url, data=json.dumps(payload, ensure_ascii=False).encode("utf-8"), headers=self._headers(), method="POST")
        with urlopen(request, timeout=self.config.timeout_seconds) as response:
            return json.loads(response.read().decode("utf-8"))

    @staticmethod
    def _extract_json(response):
        candidate = response
        # LLM Serving follows the chat-completions response shape.
        if isinstance(candidate, dict) and candidate.get("choices"):
            first = candidate["choices"][0]
            candidate = first.get("message", {}).get("content", first.get("text", first))
        for key in ("data", "output", "response", "result", "content"):
            if isinstance(candidate, dict) and key in candidate:
                candidate = candidate[key]
        if isinstance(candidate, list) and candidate:
            candidate = candidate[0]
        if isinstance(candidate, str):
            match = re.search(r"\{.*\}", candidate, re.S)
            candidate = json.loads(match.group(0) if match else candidate)
        return candidate if isinstance(candidate, dict) else {}

    def _call_llm(self, prompt):
        """Send an OpenAI-compatible chat request to Catalyst LLM Serving."""
        system = str(prompt.get("system", ""))
        user_payload = {key: value for key, value in prompt.items() if key != "system"}
        return self.transport(self.config.llm_endpoint, {
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": json.dumps(user_payload, ensure_ascii=False)},
            ],
            "temperature": 0.1,
            "response_format": {"type": "json_object"},
        })

    @staticmethod
    def _safe_record(record):
        return {
            "evidence_id": record_id(record), "case_id": record.get("id"), "case_no": record.get("case_no"),
            "title": record.get("title"), "offence": record.get("minor"), "status": record.get("status"),
            "gravity": record.get("gravity"), "station": record.get("station"), "district": record.get("district"),
            "date": record.get("date"), "time": record.get("time"), "location": record.get("location"),
            "accused": [name for name in record.get("accused", []) if is_known_identity(name)],
            "acts": record.get("acts", []), "brief": record.get("brief", ""),
        }

    def _audit(self, callback, phase, user, question, ids, response):
        if callback:
            callback("QUICKML_CALL", phase, json.dumps({
                "user": user.get("id"), "role": user.get("role"), "question": question[:300],
                "retrieved_record_ids": list(ids), "response": response if isinstance(response, str) else json.dumps(response, ensure_ascii=False)[:1200],
            }, ensure_ascii=False))

    def _rag_retrieve(self, question, allowed, user, audit_callback):
        allowed_ids = {record_id(item) for item in allowed}
        document_ids = [str(self.config.rag_record_map[item]) for item in allowed_ids if item in self.config.rag_record_map]
        if not document_ids:
            return None
        payload = {"query": question, "document_ids": document_ids, "response_format": "json"}
        raw = self.transport(self.config.rag_endpoint, payload)
        self._audit(audit_callback, "RAG_RETRIEVAL", user, question, allowed_ids, raw)
        parsed = self._extract_json(raw)
        retrieved_docs = parsed.get("retrieved_documents") or parsed.get("documents") or parsed.get("sources") or []
        reverse_map = {str(value): key for key, value in self.config.rag_record_map.items()}
        retrieved_ids = set()
        for doc in retrieved_docs:
            doc_id = str(doc.get("document_id") or doc.get("id") or "") if isinstance(doc, dict) else str(doc)
            if doc_id in reverse_map and reverse_map[doc_id] in allowed_ids:
                retrieved_ids.add(reverse_map[doc_id])
        return [item for item in allowed if record_id(item) in retrieved_ids] or None

    def answer(self, question, records, user, base_case_id=None, history=None, audit_callback=None):
        if not self.config.llm_ready:
            return None
        scoped = scope_records(records, user, base_case_id)
        if not scoped:
            return None
        mode = "quickml-rag"
        retrieved = None
        try:
            if self.config.rag_ready:
                retrieved = self._rag_retrieve(question, scoped, user, audit_callback)
        except (HTTPError, URLError, TimeoutError, ValueError, KeyError, json.JSONDecodeError):
            retrieved = None
        if not retrieved:
            # Required fallback when Catalyst Gen AI RAG is not enabled for the organisation.
            mode = "quickml-llm-manual-retrieval"
            retrieved = manual_retrieve(question, scoped, base_case_id=base_case_id)
        catalogue = [self._safe_record(item) for item in retrieved]
        allowed_ids = {item["evidence_id"] for item in catalogue}
        prompt = {
            "system": "You are a police intelligence analyst. Use ONLY supplied records. Never invent a case number, identity, location or relationship. Unknown identities are already removed and must not be inferred. Return strict JSON: answer, kind (Verified fact or Analytical lead), confidence (0-100), evidence_ids (non-empty subset of supplied evidence_id values).",
            "intent": classify_query(question), "question": question,
            "conversation_context": (history or [])[-6:], "authorised_retrieved_records": catalogue,
        }
        try:
            raw = self._call_llm(prompt)
            self._audit(audit_callback, "LLM_ANALYTICS", user, question, allowed_ids, raw)
            result = self._extract_json(raw)
            evidence_ids = {str(value) for value in result.get("evidence_ids", [])}
            if not result.get("answer") or not evidence_ids or not evidence_ids.issubset(allowed_ids):
                raise ValueError("QuickML response failed evidence validation")
            selected = [item for item in catalogue if item["evidence_id"] in evidence_ids]
            return {"answer": str(result["answer"]), "kind": result.get("kind") if result.get("kind") in {"Verified fact", "Analytical lead"} else "Analytical lead", "confidence": max(0, min(int(result.get("confidence", 70)), 100)), "evidence_ids": sorted(evidence_ids), "evidence": selected, "engine": mode, "intent": classify_query(question)}
        except (HTTPError, URLError, TimeoutError, ValueError, KeyError, TypeError, json.JSONDecodeError):
            return None

    def explain_risk(self, case, active_factors, evidence_rows, user, audit_callback=None):
        if int(case.get("risk", -1)) < 0:
            return {"status": "not-assessed", "score": None, "explanations": [], "engine": "short-circuit"}
        factors = [{"name": name, "points": int(points), "evidence_ids": list(evidence_rows.get(name, []))} for name, points in active_factors.items() if int(points) > 0]
        if not factors:
            return {"status": "assessed", "score": int(case["risk"]), "explanations": [], "engine": "deterministic"}
        if not self.config.llm_ready:
            return self._deterministic_risk(case, factors)
        allowed_ids = {str(value) for factor in factors for value in factor["evidence_ids"]}
        prompt = {"system": "Phrase one plain-English reason per supplied risk factor. Do not change points or total score. Do not add facts. Return strict JSON with explanations: [{factor, points, reason, evidence_ids}].", "risk_score_locked": int(case["risk"]), "active_factors_locked": factors}
        try:
            raw = self._call_llm(prompt)
            self._audit(audit_callback, "LLM_RISK_EXPLANATION", user, f"risk explanation {record_id(case)}", allowed_ids, raw)
            parsed = self._extract_json(raw)
            explanations = parsed.get("explanations", [])
            expected = {(item["name"], item["points"]) for item in factors}
            received = {(str(item.get("factor")), int(item.get("points", -1))) for item in explanations}
            returned_ids = {str(value) for item in explanations for value in item.get("evidence_ids", [])}
            if received != expected or not returned_ids.issubset(allowed_ids):
                raise ValueError("QuickML changed risk factors or cited unsupported evidence")
            return {"status": "assessed", "score": int(case["risk"]), "explanations": explanations, "engine": "quickml-llm"}
        except (HTTPError, URLError, TimeoutError, ValueError, KeyError, TypeError, json.JSONDecodeError):
            return self._deterministic_risk(case, factors)

    @staticmethod
    def _deterministic_risk(case, factors):
        explanations = [{"factor": item["name"], "points": item["points"], "reason": f"{item['name'].capitalize()} evidence contributes {item['points']} points.", "evidence_ids": item["evidence_ids"]} for item in factors]
        return {"status": "assessed", "score": int(case["risk"]), "explanations": explanations, "engine": "deterministic"}
