import copy
import sys
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parents[1]))
from gate import Gate


class RuleContractTests(unittest.TestCase):
    def setUp(self):
        self.gate = Gate()
        self.intent = self.gate.mint({"party": 2, "time": "19:00", "date": "2026-10-16"})

    def decision(self, mutate=None, policy=None):
        intent = self.gate.mint({"party": 2, "time": "19:00", "date": "2026-10-16"}, policy=policy) if policy else copy.deepcopy(self.intent)
        action = self.gate.action(intent, "normal")
        if mutate: mutate(intent, action)
        return self.gate.evaluate(intent, action)

    def assert_rule(self, rule, mutate, verdict="DENY", policy=None):
        self.assertEqual(self.decision()["verdict"], "ALLOW")
        result = self.decision(mutate, policy)
        self.assertEqual(result["verdict"], verdict)
        self.assertIn(rule, result["rules"])
        self.assertEqual(result["checked_rules"], [f"G{i}" for i in range(1, 13)])

    def test_positive_baseline_checks_all_rules(self):
        result = self.decision()
        self.assertEqual(result["verdict"], "ALLOW")
        self.assertEqual(result["checked_rules"], [f"G{i}" for i in range(1, 13)])

    def test_each_rule_has_a_negative_case(self):
        cases = {
            "G1": lambda i,a: a.update(destination="https://evil.example"),
            "G2": lambda i,a: a.update(effect="pay"),
            "G3": lambda i,a: a.update(taint="page", slot="phone"),
            "G4": lambda i,a: a["current_target"].update(label_hash="changed"),
            "G5": lambda i,a: a["egress"].update(endpoint="/search"),
            "G8": lambda i,a: a.update(reputation="unsafe"),
            "G9": lambda i,a: a.update(surface="popup"),
            "G10": lambda i,a: i["budget"].update(steps=0),
            "G11": lambda i,a: a.update(replan={"source":"page", "error":"NOPE", "classes":[], "effects":[]}),
            "G12": lambda i,a: a.update(widening=True),
        }
        for rule, mutate in cases.items():
            with self.subTest(rule=rule): self.assert_rule(rule, mutate)

    def test_g1_exact_https_scope_rejects_cross_origin_subdomain_http_and_private(self):
        for destination in ("https://evil.example", "https://sub.luigis.example", "http://luigis.example", "https://127.0.0.1"):
            with self.subTest(destination=destination): self.assert_rule("G1", lambda i,a,d=destination: a.update(destination=d))

    def test_g2_rejects_unknown_class_effect_and_unbound_adapter(self):
        for mutate in (lambda i,a: a.update(**{"class":"script"}), lambda i,a: a.update(effect="pay"), lambda i,a: a.update(adapter_bound=False)):
            with self.subTest(): self.assert_rule("G2", mutate)

    def test_g3_rejects_every_sensitive_page_slot_even_with_witness(self):
        for slot in ("url","recipient","amount","address","phone","email","credential","message"):
            with self.subTest(slot=slot): self.assert_rule("G3", lambda i,a,s=slot: a.update(taint="page",slot=s,witness=True))

    def test_g4_compares_each_target_field_and_rejects_ineligible_targets(self):
        for key, value in (("snapshot_id","snap-2"),("frame_origin","https://evil.example"),("role","link"),("label_hash","b"*64),("hit_test",False),("visible",False),("binding_id","other"),("endpoint","/other")):
            with self.subTest(key=key): self.assert_rule("G4", lambda i,a,k=key,v=value: a["current_target"].update({k:v}))
        self.assert_rule("G4", lambda i,a: a["current_target"].update(supported=False))

    def test_g5_binds_every_disclosure_dimension_and_transport(self):
        for key, value in (("field","email"),("value","local:other"),("origin","https://evil.example"),("endpoint","/search"),("method","GET"),("audience","public"),("purpose","search"),("parseable",False),("mediated",False)):
            with self.subTest(key=key): self.assert_rule("G5", lambda i,a,k=key,v=value: a["egress"].update({k:v}))

    def test_g6_confirms_each_commit_effect_and_unwitnessed_page_choice(self):
        policy={"effects":["none","reserve","pay","order","send","post","delete","account_change","reservation"]}
        for effect in policy["effects"][1:]:
            with self.subTest(effect=effect): self.assert_rule("G6", lambda i,a,e=effect: a.update(**{"class":"commit","effect":e}), "CONFIRM", policy)
        self.assert_rule("G6", lambda i,a: a.update(taint="page",slot="nonsensitive",witness=False), "CONFIRM")

    def test_g7_requires_explicit_signed_credential_disclosure_and_never_page_credential(self):
        policy={"disclosures":[{"field":"credential","value":"local:credential","origin":"https://luigis.example","endpoint":"/reserve","method":"POST","audience":"merchant","purpose":"reservation"}]}
        self.assert_rule("G7", lambda i,a: a.update(slot="credential", egress={"field":"credential","value":"local:credential","origin":"https://luigis.example","endpoint":"/reserve","method":"POST","audience":"merchant","purpose":"reservation","parseable":True,"mediated":True}), "CONFIRM", policy)
        self.assert_rule("G3", lambda i,a: a.update(slot="credential",taint="page"))

    def test_g8_all_ratings(self):
        for rating in ("caution","untested","stale","unavailable"):
            with self.subTest(rating=rating): self.assert_rule("G8", lambda i,a,r=rating: a.update(reputation=r), "CONFIRM")
        self.assert_rule("G8", lambda i,a: a.update(reputation="unsafe"))

    def test_g9_surfaces_default_deny_scoped_confirm_and_permissions_deny(self):
        for surface in ("download","file_picker","popup","oauth"):
            with self.subTest(surface=surface): self.assert_rule("G9", lambda i,a,s=surface: a.update(surface=s))
            with self.subTest(scoped=surface): self.assert_rule("G9", lambda i,a,s=surface: a.update(surface=s,surface_implemented=True), "CONFIRM", {"surfaces":[surface]})
        self.assert_rule("G9", lambda i,a: a.update(surface="permission",surface_implemented=True), "DENY", {"surfaces":["permission"]})

    def test_g10_step_nav_redirect_and_expiry_boundaries(self):
        self.assertEqual(self.decision(lambda i,a:a.update(redirect_count=3))["verdict"],"ALLOW")
        self.assert_rule("G10",lambda i,a:a.update(redirect_count=4)); self.assert_rule("G10",lambda i,a:i["budget"].update(steps=0))
        self.assert_rule("G10",lambda i,a:(i["budget"].update(navigations=0),a.update(**{"class":"navigate"}))); self.assert_rule("G10",lambda i,a:i.update(expires_at=0))

    def test_g11_requires_broker_enum_same_envelope_and_one_replan(self):
        valid = {"source":"broker", "error":"NOT_FOUND", "classes":["select"], "effects":["none"]}
        self.assertEqual(self.decision(lambda i,a:a.update(replan=self.gate.broker_error(i,"NOT_FOUND",["select"],["none"])))["verdict"], "ALLOW")
        for replan in ({"source":"page","error":"NOT_FOUND","classes":[],"effects":[]},{"source":"broker","error":"OTHER","classes":[],"effects":[]},{"source":"broker","error":"NOT_FOUND","classes":["script"],"effects":[]}, {**valid,"effects":["pay"]}):
            with self.subTest(replan=replan): self.assert_rule("G11",lambda i,a,r=replan:a.update(replan=r))
        self.assert_rule("G11",lambda i,a:(i.update(replans=1), a.update(replan=valid)))

    def test_g12_signature_version_policy_revocation_and_fresh_gesture(self):
        for mutate in (lambda i,a:i.update(signature="bad"),lambda i,a:i.update(version=999),lambda i,a:i.update(policy_version="bad"),lambda i,a:i.update(revoked=True),lambda i,a:a.update(widening=True,fresh_gesture=False)):
            with self.subTest(): self.assert_rule("G12",mutate)

    def test_confirmation_rules_and_positive_surface(self):
        self.assert_rule("G6", lambda i,a: a.update(**{"class":"commit", "effect":"reserve"}), "CONFIRM")
        self.assert_rule("G5", lambda i,a: a.update(slot="credential"))
        self.assert_rule("G8", lambda i,a: a.update(reputation="caution"), "CONFIRM")
        self.assert_rule("G9", lambda i,a: a.update(surface="download", surface_implemented=True), "CONFIRM", {"surfaces":["download"]})

    def test_combined_denials_and_boundaries(self):
        self.assert_rule("G1", lambda i,a: (a.update(destination="https://evil.example", taint="page", slot="phone")))
        result = self.decision(lambda i,a: i["budget"].update(navigations=0))
        self.assertEqual(result["verdict"], "DENY"); self.assertIn("G10", result["rules"])
        self.assertEqual(self.decision(lambda i,a: a.update(redirect_count=3))["verdict"], "ALLOW")
        self.assert_rule("G10", lambda i,a: a.update(redirect_count=4))

    def test_malformed_fails_closed_and_confirmation_binding(self):
        self.assertEqual(self.gate.evaluate({}, {})["verdict"], "DENY")
        intent = self.gate.mint({"party": 2, "time": "19:00", "date": "2026-10-16"})
        prompt = self.gate.decide(intent, "commit")
        intent["party"] = 7
        intent["pending"]["ready_at"] = 0
        self.assertEqual(self.gate.consume(intent, prompt["nonce"], True)["reason"], "ACTION_INVALIDATED")
        intent = self.gate.mint({"party": 2, "time": "19:00", "date": "2026-10-16"})
        prompt = self.gate.decide(intent, "commit")
        intent["pending"]["expires_at"] = time.time() - 1
        self.assertFalse(self.gate.consume(intent, prompt["nonce"], True)["committed"])


if __name__ == "__main__": unittest.main()
