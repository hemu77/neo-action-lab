import sys
import unittest
from unittest.mock import patch
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parents[1]))
from gate import Gate


class GateTests(unittest.TestCase):
    def setUp(self):
        self.gate = Gate()
        self.intent = self.gate.mint({"party": 2, "time": "19:00", "date": "2026-10-16"})

    def test_page_taint_denies_sensitive_slot(self):
        verdict = self.gate.decide(self.intent, "tainted_phone")
        self.assertEqual((verdict["verdict"], verdict["rules"]), ("DENY", ["G3"]))

    def test_deny_precedence_and_all_rules(self):
        expected = {"vip_deposit": "G2", "exfiltration": "G5", "target_swap": "G4", "same_origin_leak": "G5", "out_of_scope": "G1", "unsafe_reputation": "G8", "popup": "G9", "replan": "G11", "widening": "G12"}
        for scenario, rule in expected.items():
            with self.subTest(scenario=scenario):
                result = self.gate.decide(self.intent, scenario)
                self.assertEqual(result["verdict"], "DENY")
                self.assertIn(rule, result["rules"])

    def test_budget_and_expiry_deny(self):
        self.intent["budget"]["steps"] = 0
        self.assertIn("G10", self.gate.decide(self.intent, "normal")["rules"])

    def test_sensitive_data_requires_confirmation(self):
        binding = dict(self.intent["disclosures"][0], field="credential", value="local:credential")
        self.intent = self.gate.mint({"party":2,"time":"19:00","date":"2026-10-16"}, policy={"disclosures":[binding]})
        decision = self.gate.decide(self.intent, "sensitive_data")
        self.assertEqual((decision["verdict"], decision["rules"]), ("CONFIRM", ["G7"]))
        self.intent["budget"]["steps"] = 20
        self.intent["expires_at"] = 0
        self.assertIn("G10", self.gate.decide(self.intent, "normal")["rules"])

    def test_commit_requires_single_use_confirm(self):
        pending = self.gate.decide(self.intent, "commit")
        self.assertEqual(pending["verdict"], "CONFIRM")
        self.intent["pending"]["ready_at"] = 0
        self.assertTrue(self.gate.consume(self.intent, pending["nonce"], True)["committed"])
        self.assertFalse(self.gate.consume(self.intent, pending["nonce"], True)["committed"])

    def test_last_admitted_step_can_confirm(self):
        self.intent["budget"]["steps"] = 1
        decision = self.gate.decide(self.intent, "commit")
        self.intent["budget"]["steps"] -= 1
        self.intent["pending"]["ready_at"] = 0
        self.assertTrue(self.gate.consume(self.intent, decision["nonce"], True)["committed"])
        self.assertIsNone(self.intent["pending"])

    def test_changed_contract_or_expired_intent_cannot_commit(self):
        for field, value in (("time", "19:30"), ("date", "2026-10-17"), ("phone_mask", "changed"), ("expires_at", 0)):
            with self.subTest(field=field):
                self.setUp()
                decision = self.gate.decide(self.intent, "commit")
                self.intent["pending"]["ready_at"] = 0
                self.intent[field] = value
                self.assertEqual(self.gate.consume(self.intent, decision["nonce"], True)["reason"], "ACTION_INVALIDATED")
                self.assertIsNone(self.intent["reservation"])
                self.assertIsNone(self.intent["pending"])

    def test_cancel_is_available_before_arming_and_after_expiry(self):
        for expired in (False, True):
            decision = self.gate.decide(self.intent, "commit")
            if expired: self.intent["pending"]["expires_at"] = 0
            self.assertEqual(self.gate.consume(self.intent, decision["nonce"], False)["reason"], "CANCELLED")
            self.assertIsNone(self.intent["pending"])
            self.assertIsNone(self.intent["reservation"])

    def test_grant_expiry_boundary_and_early_accept(self):
        for early in (False, True):
            decision = self.gate.decide(self.intent, "commit")
            boundary = self.intent["pending"]["ready_at"] - .01 if early else self.intent["pending"]["expires_at"]
            with patch("gate.time.time", return_value=boundary):
                self.assertFalse(self.gate.consume(self.intent, decision["nonce"], True)["committed"])
            self.assertIsNone(self.intent["pending"])

    def test_evaluation_is_pure_and_denial_overrides_confirmation(self):
        action = self.gate.action(self.intent, "commit")
        action["egress_ok"] = False
        self.assertEqual(self.gate.evaluate(self.intent, action)["verdict"], "DENY")
        self.assertIsNone(self.intent["pending"])
        action["egress_ok"] = True
        self.assertEqual(self.gate.evaluate(self.intent, action)["verdict"], "CONFIRM")
        self.assertIsNone(self.intent["pending"])

    def test_navigation_budget_and_noncommit_confirmation(self):
        self.intent["budget"]["navigations"] = 0
        self.assertIn("G10", self.gate.decide(self.intent, "normal")["rules"])
        decision = self.gate.decide(self.intent, "caution")
        self.intent["pending"]["ready_at"] = 0
        self.assertFalse(self.gate.consume(self.intent, decision["nonce"], True)["committed"])
        self.assertIsNone(self.intent["reservation"])

    def test_boundary_inputs_fail_with_validation_error(self):
        for field, value in (("time", []), ("time", {}), ("date", []), ("party", True), ("party", 0)):
            with self.subTest(field=field, value=value):
                payload = {"party": 2, "time": "19:00", "date": "2026-10-16", field: value}
                with self.assertRaises(ValueError): self.gate.mint(payload)


if __name__ == "__main__":
    unittest.main()
