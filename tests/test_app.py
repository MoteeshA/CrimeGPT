import tempfile
import unittest
import os
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

    def test_health_and_readiness(self):
        self.assertEqual(self.client.get("/health").json["status"], "ok")
        self.assertEqual(self.client.get("/ready").json["status"], "ready")

    def test_security_headers_are_present(self):
        response = self.client.get("/")
        self.assertEqual(response.headers["X-Frame-Options"], "DENY")
        self.assertEqual(response.headers["X-Content-Type-Options"], "nosniff")
        self.assertIn("frame-ancestors 'none'", response.headers["Content-Security-Policy"])
        self.assertIn("https://static.zohocdn.com", response.headers["Content-Security-Policy"])

    def test_catalyst_logout_uses_web_sdk(self):
        os.environ["CATALYST_AUTH_ENABLED"] = "1"
        response = self.client.get("/logout")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"catalyst.auth.signOut", response.data)
        self.assertIn(b"http://localhost/", response.data)
        self.assertNotIn(b"catalystserverless.in", response.data)
        os.environ["CATALYST_AUTH_ENABLED"] = "0"

    def test_policymaker_cannot_ingest_or_query_cases(self):
        self.login_as("POL001")
        self.assertEqual(self.client.get("/fir/new").status_code, 403)
        self.assertEqual(self.client.post("/api/case/417/ask", json={"question": "Where?"}).status_code, 403)

    def test_unauthenticated_api_is_not_executed(self):
        response = self.client.post("/api/case/417/ask", json={"question": "Where?"})
        self.assertEqual(response.status_code, 302)


if __name__ == "__main__":
    unittest.main()
