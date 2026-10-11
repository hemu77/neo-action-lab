import http.client
import json
import sys
import threading
import time
import unittest
from unittest.mock import patch
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parents[1]))
from server import make_server


class ServerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = make_server("127.0.0.1", 0)
        cls.port = cls.server.server_address[1]
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown(); cls.server.server_close()

    def request(self, method, path, body=None, cookie=None, origin=True, host=None):
        conn = http.client.HTTPConnection("127.0.0.1", self.port)
        headers = {"Host": host or f"127.0.0.1:{self.port}"}
        if origin: headers["Origin"] = f"http://127.0.0.1:{self.port}"
        if cookie: headers["Cookie"] = cookie
        if body is not None: headers["Content-Type"] = "application/json"
        conn.request(method, path, body=json.dumps(body) if isinstance(body, dict) else body, headers=headers)
        response = conn.getresponse(); raw = response.read(); conn.close()
        return response.status, dict(response.getheaders()), json.loads(raw or b"{}")

    def bootstrap(self):
        status, headers, _ = self.request("GET", "/api/state", origin=False)
        return headers["Set-Cookie"].split(";", 1)[0]

    def setUp(self):
        with self.server.lock:
            self.server.sessions.clear()

    def mint(self, cookie):
        return self.request("POST", "/api/intent", {"party": 2, "time": "19:00", "date": "2026-10-16"}, cookie)

    def test_rejects_malformed_and_hostile_mutations(self):
        cookie = self.bootstrap()
        self.assertEqual(self.request("POST", "/api/intent", b"{", cookie)[0], 400)
        self.assertEqual(self.request("POST", "/api/intent", {"party": 2, "time": "19:00", "date": "2026-10-16"}, cookie, host="evil.example")[0], 403)
        self.assertEqual(self.request("POST", "/api/intent", {"party": 2, "time": "19:00", "date": "2026-10-16"}, cookie, origin=False)[0], 403)

    def test_isolation_replay_and_static_security_headers(self):
        one, two = self.bootstrap(), self.bootstrap()
        payload = {"party": 2, "time": "19:00", "date": "2026-10-16"}
        self.assertEqual(self.request("POST", "/api/intent", payload, one)[0], 200)
        self.assertIsNone(self.request("GET", "/api/state", cookie=two, origin=False)[2]["intent"])
        for _ in range(4): self.assertEqual(self.request("POST", "/api/step", {"scenario": "normal"}, one)[0], 200)
        state = self.request("GET", "/api/state", cookie=one, origin=False)[2]
        nonce = state["pending"]["nonce"]
        time.sleep(.55)
        self.assertEqual(self.request("POST", "/api/confirm", {"nonce": nonce, "accept": True}, one)[0], 200)
        self.assertEqual(self.request("POST", "/api/confirm", {"nonce": nonce, "accept": True}, one)[0], 409)
        status, headers, _ = self.request("GET", "/../server.py", origin=False)
        self.assertEqual(status, 404); self.assertIn("default-src 'self'", headers["Content-Security-Policy"])

    def test_bounded_sessions_expire_and_reject_spoofed_host(self):
        with patch("server.MAX_SESSIONS", 2):
            self.bootstrap(); self.bootstrap()
            self.assertEqual(self.request("GET", "/api/state", origin=False)[0], 503)
            self.assertEqual(len(self.server.sessions), 2)
            with self.server.lock:
                for session in self.server.sessions.values(): session["last_access"] = 0
            self.assertEqual(self.request("GET", "/api/state", origin=False)[0], 200)
            self.assertEqual(len(self.server.sessions), 1)
        self.assertEqual(self.request("GET", "/api/state", host="evil.example")[0], 403)

    def test_budget_probe_stops_until_reset_and_exports_no_nonce(self):
        cookie = self.bootstrap(); self.mint(cookie)
        status, _, state = self.request("POST", "/api/step", {"scenario": "budget"}, cookie)
        self.assertEqual(status, 200)
        self.assertEqual(state["phase"], "stopped")
        self.assertEqual(state["audit"][-1]["rules"], ["G10"])
        self.assertEqual(self.request("POST", "/api/step", {"scenario": "normal"}, cookie)[0], 409)
        self.assertEqual(self.request("POST", "/api/reset", {}, cookie)[0], 200)
        self.mint(cookie)
        for _ in range(4): self.request("POST", "/api/step", {"scenario": "normal"}, cookie)
        exported = self.request("GET", "/api/export", cookie=cookie)[2]
        self.assertNotIn("pending", exported)
        self.assertNotIn("nonce", json.dumps(exported))
        self.assertNotIn("action_record", json.dumps(exported))

    def test_malformed_types_and_missing_session_are_rejected(self):
        cookie = self.bootstrap()
        self.assertEqual(self.request("POST", "/api/intent", {"party": 2, "time": [], "date": "2026-10-16"}, cookie)[0], 400)
        self.assertEqual(self.mint(cookie)[0], 200)
        self.assertEqual(self.mint(cookie)[0], 409)
        self.assertEqual(self.request("POST", "/api/step", {"scenario": {}}, cookie)[0], 400)
        self.assertEqual(self.request("POST", "/api/reset", {})[0], 401)
        self.assertEqual(self.request("POST", "/api/confirm", {"nonce":"invalid","accept":True,"probe":{}}, cookie)[0], 400)

    def test_last_step_commit_is_admitted_once_via_http(self):
        cookie = self.bootstrap(); self.mint(cookie)
        for _ in range(16): self.request("POST", "/api/step", {"scenario": "tainted_phone"}, cookie)
        for _ in range(4): status, _, state = self.request("POST", "/api/step", {"scenario": "normal"}, cookie)
        self.assertEqual(state["intent"]["budget"]["steps"], 0)
        self.assertIsNotNone(state["pending"])
        nonce = state["pending"]["nonce"]
        with self.server.lock:
            next(iter(self.server.sessions.values()))["intent"]["pending"]["ready_at"] = 0
        status, _, state = self.request("POST", "/api/confirm", {"nonce": nonce, "accept": True}, cookie)
        self.assertEqual(status, 200); self.assertEqual(state["phase"], "complete")
        self.assertIsNone(state["pending"])
        self.assertEqual(self.request("POST", "/api/step", {"scenario": "normal"}, cookie)[0], 409)

    def test_all_ui_probes_reach_the_expected_gate_rule(self):
        from gate import SCENARIOS
        cookie = self.bootstrap()
        for scenario, label, _ in SCENARIOS:
            if scenario == "normal": continue
            with self.subTest(scenario=scenario):
                self.request("POST", "/api/reset", {}, cookie)
                self.mint(cookie)
                status, _, state = self.request("POST", "/api/step", {"scenario":scenario}, cookie)
                self.assertEqual(status, 200)
                self.assertIn(label.rsplit(" · ", 1)[1], state["audit"][-1]["rules"])
                self.assertEqual(state["audit"][-1]["verdict"], "CONFIRM" if scenario in {"caution", "ambiguous_choice"} else "DENY")

    def test_noncommit_confirmation_and_postprompt_target_swap(self):
        cookie = self.bootstrap(); self.mint(cookie)
        _, _, state = self.request("POST", "/api/step", {"scenario":"caution"}, cookie)
        with patch("gate.time.time", return_value=state["pending"]["ready_at"]):
            status, _, state = self.request("POST", "/api/confirm", {"nonce":state["pending"]["nonce"],"accept":True}, cookie)
        self.assertEqual(status, 200)
        self.assertIsNone(state["reservation"])
        self.assertEqual(state["audit"][-1]["rules"], ["G8"])
        for _ in range(4): _, _, state = self.request("POST", "/api/step", {"scenario":"normal"}, cookie)
        nonce = state["pending"]["nonce"]
        with patch("gate.time.time", return_value=state["pending"]["ready_at"]):
            status, _, state = self.request("POST", "/api/confirm", {"nonce":nonce,"accept":True,"probe":"target_swap"}, cookie)
        self.assertEqual(status, 200)
        self.assertIsNone(state["reservation"])
        self.assertEqual(state["audit"][-1]["rules"], ["G4"])
        self.assertEqual(state["audit"][-1]["verdict"], "DENY")
        self.assertEqual(self.request("POST", "/api/confirm", {"nonce":nonce,"accept":True}, cookie)[0], 409)


if __name__ == "__main__":
    unittest.main()
