import unittest

from intelligence_engine import CatalystQuickMLEngine, QuickMLConfig, classify_query, scope_records


RECORDS = [
    {"id": 1, "crime_no": "FIR-1", "case_no": "1", "title": "Market robbery", "minor": "Robbery", "district": "Bengaluru", "station": "Central PS", "officer": "Asha", "location": "Market", "date": "2026-07-01", "time": "23:00", "accused": ["Ravi Naik"], "brief": "Wallet taken"},
    {"id": 2, "crime_no": "FIR-2", "case_no": "2", "title": "Unknown suspect", "minor": "Robbery", "district": "Mysuru", "station": "West PS", "officer": "Bala", "location": "Bus stand", "date": "2026-07-02", "time": "11:00", "accused": ["Unknown A1"], "brief": "Phone taken"},
]


def configured():
    return QuickMLConfig(llm_endpoint="https://quickml.invalid/llm", org_id="org", endpoint_key="key", access_token="oauth")


class IntelligenceEngineTests(unittest.TestCase):
    def test_query_classification_and_routing(self):
        self.assertEqual(classify_query("Compare night burglaries in Bengaluru and Mysuru"), "comparison")
        self.assertEqual(classify_query("Which accused appear across three districts?"), "network")
        self.assertEqual(classify_query("What changed this month?"), "trend")
        self.assertEqual(classify_query("Show robberies within five kilometres"), "spatial")

    def test_role_scope_is_applied_before_retrieval(self):
        investigator = scope_records(RECORDS, {"role": "investigator", "name": "Asha", "unit": "Central PS"})
        self.assertEqual([item["crime_no"] for item in investigator], ["FIR-1"])
        analyst = scope_records(RECORDS, {"role": "analyst", "name": "X", "unit": "SCRB"})
        self.assertEqual(len(analyst), 2)
        policymaker = scope_records(RECORDS, {"role": "policymaker", "name": "P", "unit": "HQ"})
        self.assertEqual(policymaker[0]["accused"], [])
        self.assertEqual(policymaker[0]["brief"], "")

    def test_unknown_identity_is_removed_from_model_context(self):
        captured = {}
        def transport(_url, payload):
            captured.update(payload)
            return {"answer": "One record.", "kind": "Verified fact", "confidence": 90, "evidence_ids": ["FIR-2"]}
        engine = CatalystQuickMLEngine(configured(), transport)
        result = engine.answer("Summarise", RECORDS, {"id": "a", "role": "analyst"}, base_case_id=2)
        self.assertIsNotNone(result)
        selected = next(item for item in captured["authorised_retrieved_records"] if item["evidence_id"] == "FIR-2")
        self.assertEqual(selected["accused"], [])

    def test_no_fabrication_rejects_unretrieved_evidence_id(self):
        def transport(_url, _payload):
            return {"answer": "Invented case", "kind": "Verified fact", "confidence": 100, "evidence_ids": ["FIR-999"]}
        result = CatalystQuickMLEngine(configured(), transport).answer(
            "Market robbery", RECORDS, {"id": "a", "role": "analyst"}
        )
        self.assertIsNone(result)

    def test_not_assessed_short_circuits_model_call(self):
        calls = []
        def transport(url, payload):
            calls.append((url, payload))
            raise AssertionError("model must not be called")
        result = CatalystQuickMLEngine(configured(), transport).explain_risk(
            {"crime_no": "FIR-1", "risk": -1}, {"gravity": 25}, {"gravity": ["FIR-1"]}, {"id": "a", "role": "analyst"}
        )
        self.assertEqual(result["status"], "not-assessed")
        self.assertEqual(calls, [])

    def test_risk_score_and_factor_points_are_locked(self):
        def transport(_url, _payload):
            return {"explanations": [{"factor": "gravity", "points": 99, "reason": "Changed", "evidence_ids": ["FIR-1"]}]}
        result = CatalystQuickMLEngine(configured(), transport).explain_risk(
            {"crime_no": "FIR-1", "risk": 65}, {"gravity": 25}, {"gravity": ["FIR-1"]}, {"id": "a", "role": "analyst"}
        )
        self.assertEqual(result["score"], 65)
        self.assertEqual(result["engine"], "deterministic")
        self.assertEqual(result["explanations"][0]["points"], 25)


if __name__ == "__main__":
    unittest.main()
