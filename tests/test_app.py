import tempfile
import unittest
from pathlib import Path

import app as crimegpt


class CrimeGPTTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        crimegpt.DB_PATH = Path(self.tempdir.name) / "test.db"
        crimegpt.app.config.update(TESTING=True, SECRET_KEY="test-secret")
        crimegpt.init_db()
        self.client = crimegpt.app.test_client()

    def tearDown(self):
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


if __name__ == "__main__":
    unittest.main()
