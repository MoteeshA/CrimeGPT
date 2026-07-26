import tempfile
import unittest
import os
from io import BytesIO
from pathlib import Path

import app as crimegpt


class CrimeGPTTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        crimegpt.DB_PATH = Path(self.tempdir.name) / "test.db"
        crimegpt.app.config.update(TESTING=True, SECRET_KEY="test-secret")
        self.auth_setting = os.environ.get("CATALYST_AUTH_ENABLED")
        os.environ["CATALYST_AUTH_ENABLED"] = "0"
        crimegpt.init_db()
        self.client = crimegpt.app.test_client()

    def tearDown(self):
        if self.auth_setting is None:
            os.environ.pop("CATALYST_AUTH_ENABLED", None)
        else:
            os.environ["CATALYST_AUTH_ENABLED"] = self.auth_setting
        self.tempdir.cleanup()

    def login_as(self, officer_id):
        with self.client.session_transaction() as session:
            session["officer_id"] = officer_id

    def test_placeholder_identities_never_match(self):
        self.assertEqual(crimegpt.person_name_score("Unknown A1", "Unknown A17"), 0)
        self.assertEqual(crimegpt.person_name_score("Unknown A1", "Unknown A2"), 0)
        self.assertTrue(crimegpt.is_placeholder_identity("Unknown suspect 4"))

    def test_real_name_variants_can_match(self):
        self.assertGreaterEqual(crimegpt.person_name_score("R. Naik", "Ravi Naik"), 88)

    def test_unknown_identity_does_not_create_cross_case_lead(self):
        linked_ids = {case["id"] for case in crimegpt.linked_cases(501)}
        self.assertNotIn(990, linked_ids)
        self.assertNotIn(417, linked_ids)

    def test_core_authenticated_pages(self):
        self.login_as("INV001")
        for path in ("/cases", "/dashboard", "/case/417"):
            self.assertEqual(self.client.get(path).status_code, 200)

    def test_policymaker_cannot_open_case_board(self):
        self.login_as("POL001")
        response = self.client.get("/case/417")
        self.assertEqual(response.status_code, 302)
        self.assertIn("/dashboard", response.location)

    def test_contextual_answer_has_evidence(self):
        self.login_as("INV001")
        response = self.client.post("/api/case/417/ask", json={"question": "Where did this happen?"})
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.json["evidence"])
        self.assertEqual(response.json["kind"], "Verified fact")

    def test_greeting_does_not_dump_case_evidence(self):
        self.login_as("INV001")
        response = self.client.post("/api/case/417/ask", json={"question": "hello Hello"})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json["kind"], "Conversation")
        self.assertEqual(response.json["engine"], "conversational-router")
        self.assertEqual(response.json["evidence"], [])
        self.assertNotIn("concerns", response.json["answer"])

    def test_this_incident_does_not_inherit_previous_link_intent(self):
        self.login_as("INV001")
        self.client.post("/api/case/501/ask", json={"question": "Is this accused linked to other cases?"})
        response = self.client.post("/api/case/501/ask", json={"question": "Where and when did this incident occur?"})
        self.assertEqual(response.status_code, 200)
        self.assertIn("Richmond Road", response.json["answer"])
        self.assertEqual([item["field"] for item in response.json["evidence"]], ["Location", "IncidentFromDate"])
        self.assertFalse(response.json["context_used"])

    def test_health_and_readiness(self):
        self.assertEqual(self.client.get("/health").json["status"], "ok")
        self.assertEqual(self.client.get("/ready").json["status"], "ready")

    def test_security_headers_are_present(self):
        response = self.client.get("/")
        self.assertEqual(response.headers["X-Frame-Options"], "DENY")
        self.assertEqual(response.headers["X-Content-Type-Options"], "nosniff")
        self.assertIn("frame-ancestors 'none'", response.headers["Content-Security-Policy"])
        self.assertIn("https://static.zohocdn.com", response.headers["Content-Security-Policy"])
        self.assertIn("worker-src 'self' blob:", response.headers["Content-Security-Policy"])
        self.assertIn("https://tile.openstreetmap.org", response.headers["Content-Security-Policy"])
        self.assertIn("https://*.basemaps.cartocdn.com", response.headers["Content-Security-Policy"])

    def test_restricted_demo_login(self):
        response = self.client.post("/", data={"officer_id": "DEMO", "password": "DEMO"})
        self.assertEqual(response.status_code, 302)
        with self.client.session_transaction() as session:
            self.assertEqual(session["demo_identity"]["role"], "investigator")

    def test_catalyst_logout_uses_web_sdk(self):
        os.environ["CATALYST_AUTH_ENABLED"] = "1"
        response = self.client.get("/logout")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"catalyst.auth.signOut", response.data)
        self.assertIn(b"https://localhost/", response.data)
        self.assertNotIn(b"catalystserverless.in", response.data)
        os.environ["CATALYST_AUTH_ENABLED"] = "0"

    def test_policymaker_cannot_ingest_or_query_cases(self):
        self.login_as("POL001")
        self.assertEqual(self.client.get("/fir/new").status_code, 403)
        self.assertEqual(self.client.post("/api/case/417/ask", json={"question": "Where?"}).status_code, 403)

    def test_unauthenticated_api_is_not_executed(self):
        response = self.client.post("/api/case/417/ask", json={"question": "Where?"})
        self.assertEqual(response.status_code, 302)

    def test_kannada_question_is_detected_and_evidence_grounded(self):
        self.login_as("INV001")
        response = self.client.post("/api/case/417/ask", json={"question": "ಈ ಘಟನೆ ಎಲ್ಲಿ ನಡೆಯಿತು?"})
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.json["evidence"])

    def test_pdf_export_is_a_real_pdf(self):
        self.login_as("INV001")
        self.client.post("/api/case/417/ask", json={"question": "Where did this happen?"})
        response = self.client.get("/case/417/conversation.pdf")
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.data.startswith(b"%PDF"))
        self.assertGreater(len(response.data), 1000)

    def test_supervisor_can_export_backup_and_investigator_cannot(self):
        self.login_as("INV001")
        self.assertEqual(self.client.get("/api/admin/backup").status_code, 403)
        self.login_as("SUP001")
        response = self.client.get("/api/admin/backup")
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.data.startswith(b"SQLite format 3"))

    def test_cctns_csv_import_is_mapped_and_deduplicated(self):
        self.login_as("ANL001")
        payload = b"FIR No,Police Station,District Name,Incident Date,Incident Time,Place of Occurrence,Offence,Accused Names,Sections\n900001,Test PS,Mysuru,26 Jul 2026,23:10,Market Road,Robbery,Test Person,BNS 309\n"
        first = self.client.post("/api/admin/import-cctns", data={"dataset": (BytesIO(payload), "authorised.csv")}, content_type="multipart/form-data")
        self.assertEqual(first.status_code, 201)
        self.assertEqual(first.json["accepted"], 1)
        second = self.client.post("/api/admin/import-cctns", data={"dataset": (BytesIO(payload), "authorised.csv")}, content_type="multipart/form-data")
        self.assertEqual(second.status_code, 409)

    def test_unlabelled_model_is_never_claimed_as_validated(self):
        self.login_as("ANL001")
        response = self.client.get("/api/model/evaluation")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json["status"], "not-validated")

    def test_permissions_are_role_specific(self):
        self.login_as("POL001")
        response = self.client.get("/api/admin/permissions")
        self.assertEqual(response.json["permissions"], ["aggregate-dashboard:read", "demographics:aggregate", "early-warning:read"])
        self.assertIsNone(response.json["matrix"])

    def test_public_reference_risk_is_not_presented_as_assessed(self):
        with crimegpt.get_db() as db:
            db.execute("UPDATE cases SET risk_score=90, brief_facts=? WHERE id=417", ("PUBLIC-RECORD REFERENCE — REDACTED FOR DEVELOPMENT USE",))
        self.login_as("INV001")
        response = self.client.get("/cases")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Not assessed", response.data)
        self.assertNotIn(b"90/100", response.data)

    def test_demographic_analytics_suppresses_small_groups(self):
        self.login_as("ANL001")
        for case_id in (417, 388):
            response = self.client.post(f"/api/admin/case/{case_id}/demographics", json={"age_band": "25-34", "gender": "female", "locality_type": "urban", "occupation_group": "service"})
            self.assertEqual(response.status_code, 201)
        response = self.client.get("/api/analytics/socio-demographics?dimension=age_band")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json["groups"], [])
        self.assertEqual(response.json["suppressed_record_count"], 2)
        self.assertFalse(response.json["individual_records_exposed"])

    def test_behavioral_profile_rejects_unknown_and_describes_known_identity(self):
        self.login_as("ANL001")
        self.assertEqual(self.client.post("/api/analytics/behavioral-profile", json={"identity": "Unknown A1"}).status_code, 400)
        response = self.client.post("/api/analytics/behavioral-profile", json={"identity": "Ravi Naik"})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json["classification"], "descriptive-record-pattern")
        self.assertGreaterEqual(response.json["record_count"], 2)
        self.assertTrue(response.json["evidence_ids"])

    def test_early_warning_feed_is_human_review_only(self):
        self.login_as("SUP001")
        response = self.client.get("/api/alerts/early-warning")
        self.assertEqual(response.status_code, 200)
        self.assertFalse(response.json["automated_enforcement"])

    def test_only_supervisor_can_confirm_model_outcome(self):
        with crimegpt.get_db() as db:
            db.execute("INSERT INTO model_predictions(case_id,model_version,score,features_json,explanation_json,created_at) VALUES (?,?,?,?,?,?)", (417, "test", 82, "{}", "{}", "2026-07-26T00:00:00"))
        self.login_as("ANL001")
        self.assertEqual(self.client.post("/api/model/outcome/417", json={"outcome": True}).status_code, 403)
        self.login_as("SUP001")
        response = self.client.post("/api/model/outcome/417", json={"outcome": True})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json["status"], "evaluation-label-only")

    def test_production_readiness_never_claims_unapproved_external_gates(self):
        self.login_as("SUP001")
        response = self.client.get("/api/admin/production-readiness")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json["status"], "gated")
        self.assertFalse(response.json["all_gates_complete"])
        self.assertIn("legal_privacy_review", response.json["checks"])


if __name__ == "__main__":
    unittest.main()
