from __future__ import annotations

import argparse
import copy
import json
import secrets
import threading
import time
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from gate import Gate, RULES, SCENARIOS

ROOT = Path(__file__).resolve().parent
STATIC = ROOT / "static"
MAX_BODY = 4096
MAX_SESSIONS = 64
SESSION_TTL = 1800


def audit(session, component, action, decision, taint="user"):
    session["sequence"] = session.get("sequence", 0) + 1
    session["audit"].append({"seq": session["sequence"], "component": component, "action": action,
        "verdict": decision["verdict"], "rules": decision["rules"], "checked_rules": decision.get("checked_rules", decision["rules"]), "reason": decision["reason"], "taint": taint, "timestamp": int(time.time())})
    del session["audit"][:-200]


class Handler(BaseHTTPRequestHandler):
    server: "PrototypeServer"
    def log_message(self, *_): pass
    def end_headers(self):
        self.send_header("Content-Security-Policy", "default-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'")
        self.send_header("X-Content-Type-Options", "nosniff"); self.send_header("Referrer-Policy", "no-referrer")
        super().end_headers()
    def _send(self, status, value, cookie=None):
        data = json.dumps(value, separators=(",", ":")).encode()
        self.send_response(status); self.send_header("Content-Type", "application/json; charset=utf-8"); self.send_header("Cache-Control", "no-store")
        if cookie: self.send_header("Set-Cookie", cookie)
        self.send_header("Content-Length", str(len(data))); self.end_headers(); self.wfile.write(data)
    def _session(self, create=True):
        parsed = SimpleCookie(self.headers.get("Cookie")); morsel = parsed.get("neo_session")
        sid = morsel.value if morsel else None
        with self.server.lock:
            now = time.time()
            for expired in [key for key, value in self.server.sessions.items() if now - value["last_access"] >= SESSION_TTL]:
                self.server.gate.release(self.server.sessions[expired]["intent"])
                del self.server.sessions[expired]
            if sid and sid in self.server.sessions:
                self.server.sessions[sid]["last_access"] = now
                return sid, self.server.sessions[sid], None
            if not create: return None, None, None
            if len(self.server.sessions) >= MAX_SESSIONS: return None, None, None
            sid = secrets.token_urlsafe(24); session = {"id": sid, "intent": None, "phase": "idle", "audit": [], "last_access": now}; self.server.sessions[sid] = session
        return sid, session, f"neo_session={sid}; HttpOnly; SameSite=Strict; Path=/"
    def _trusted_mutation(self):
        host = self.headers.get("Host", ""); expected = f"127.0.0.1:{self.server.server_address[1]}"
        return host == expected and self.headers.get("Origin") == "http://" + expected
    def _json(self):
        try:
            length = int(self.headers.get("Content-Length", "-1"))
            if length < 0 or length > MAX_BODY: raise ValueError()
            value = json.loads(self.rfile.read(length))
            if not isinstance(value, dict): raise ValueError()
            return value
        except Exception: raise ValueError("invalid JSON body")
    def _state(self, session):
        intent = session["intent"]
        public_intent = None if not intent else {key: intent[key] for key in ("id", "origin", "party", "time", "date", "phone_mask", "budget", "expires_at")}
        pending = intent and intent.get("pending")
        if pending: pending = {key: pending[key] for key in ("nonce", "action", "origin", "data", "expires_at", "ready_at")}
        return copy.deepcopy({"intent": public_intent, "phase": session["phase"], "step_index": intent["step_index"] if intent else 0,
          "audit": session["audit"], "pending": pending, "reservation": intent and intent.get("reservation"),
          "scenarios": [{"id": a, "label": b, "description": c} for a,b,c in SCENARIOS], "rules": [{"id": a,"title":b,"description":c} for a,b,c in RULES]})
    def do_GET(self):
        if self.headers.get("Host") != f"127.0.0.1:{self.server.server_address[1]}": return self._send(403, {"error":"untrusted host"})
        if self.headers.get("Sec-Fetch-Site") == "cross-site": return self._send(403, {"error":"cross-site request denied"})
        if self.path == "/api/state":
            with self.server.lock:
                _, session, cookie = self._session()
                if not session: return self._send(503, {"error":"local session capacity reached"})
                snapshot = self._state(session)
            return self._send(200, snapshot, cookie)
        if self.path == "/api/export":
            with self.server.lock:
                _, session, _ = self._session(False)
                if not session: return self._send(401, {"error":"session required"})
                snapshot = self._state(session)
            return self._send(200, {k:v for k,v in snapshot.items() if k != "pending"})
        route = "/index.html" if self.path == "/" else self.path
        allowed = {"/index.html", "/app.js", "/style.css"}
        if route not in allowed: return self._send(404, {"error":"not found"})
        path = STATIC / route.lstrip("/")
        if not path.is_file(): return self._send(404, {"error":"not found"})
        content = path.read_bytes(); types = {".html":"text/html", ".js":"application/javascript", ".css":"text/css"}
        self.send_response(200); self.send_header("Content-Type", types[path.suffix] + "; charset=utf-8"); self.send_header("Content-Length", str(len(content))); self.end_headers(); self.wfile.write(content)
    def do_POST(self):
        if not self._trusted_mutation(): return self._send(403, {"error":"untrusted origin"})
        try: payload = self._json()
        except ValueError as err: return self._send(400, {"error":str(err)})
        if self.path not in {"/api/intent", "/api/step", "/api/confirm", "/api/reset"}: return self._send(404,{"error":"not found"})
        _, session, _ = self._session(False)
        if not session: return self._send(401,{"error":"session required"})
        with self.server.lock:
            if self.path == "/api/reset":
                self.server.gate.release(session["intent"])
                session.update({"intent":None,"phase":"idle","audit":[],"sequence":0})
                return self._send(200, self._state(session))
            if self.path == "/api/intent":
                if session["intent"]: return self._send(409, {"error":"reset the current task before approving a new intent"})
                try: session["intent"] = self.server.gate.mint(payload)
                except ValueError as err: return self._send(400, {"error":str(err)})
                session["phase"] = "active"
                audit(session, "minter", "mint intent", self.server.gate.trace_step(session["intent"], 1))
                audit(session, "compiler", "compile fixed program", self.server.gate.trace_step(session["intent"], 2))
                return self._send(200,self._state(session))
            intent = session.get("intent")
            if not intent: return self._send(409,{"error":"intent required"})
            if self.path == "/api/step":
                scenario=payload.get("scenario")
                if not isinstance(scenario, str): return self._send(400,{"error":"invalid scenario"})
                if scenario not in {x[0] for x in SCENARIOS}: return self._send(400,{"error":"invalid scenario"})
                if session["phase"] in {"complete", "stopped"}: return self._send(409,{"error":"task complete or stopped; reset to begin again"})
                if intent.get("pending"): intent["pending"] = None
                session["phase"] = "active"
                if scenario == "budget": intent["budget"]["steps"] = 0
                if scenario == "normal":
                    action = self.server.gate.action(intent, scenario)
                    decision = self.server.gate.decide(intent, scenario, action)
                else: action, decision = self.server.gate.probe(intent, scenario)
                audit(session,"gate",action["name"],decision,action["taint"])
                intent["budget"]["steps"] = max(0, intent["budget"]["steps"] - 1)
                if decision["verdict"]=="ALLOW" and scenario=="normal":
                    intent["step_index"]+=1; intent["navigations"]+=int(intent["step_index"]==1); intent["budget"]["navigations"]-=int(intent["step_index"]==1); session["phase"]="active"
                    if intent["step_index"] == 1:
                        audit(session,"snapshot","enumerate supported slots",self.server.gate.trace_step(intent,4),"page")
                        audit(session,"reader","parse enumerated handle",self.server.gate.trace_step(intent,5),"page")
                elif decision["verdict"]=="CONFIRM": session["phase"]="awaiting_confirmation"
                elif scenario == "normal": session["phase"]="stopped"
                if (decision["verdict"] == "DENY" and "G10" in decision["rules"]) or (intent["budget"]["steps"] == 0 and not intent["pending"]): session["phase"] = "stopped"
                return self._send(200,self._state(session))
            if self.path == "/api/confirm":
                if type(payload.get("nonce")) is not str or type(payload.get("accept")) is not bool: return self._send(400,{"error":"invalid confirmation"})
                if set(payload) - {"nonce", "accept", "probe"} or payload.get("probe") not in (None, "target_swap"): return self._send(400,{"error":"invalid confirmation probe"})
                if payload.get("probe") == "target_swap":
                    pending = intent["pending"]
                    if not pending or pending["nonce"] != payload["nonce"] or not payload["accept"]: return self._send(409,{"error":"active grant required"})
                    pending["action_record"]["current_target"]["label_hash"] = "b" * 64
                    denied = self.server.gate.evaluate(intent,pending["action_record"],admitted=True)
                    self.server.gate.consume(intent,payload["nonce"],True)
                    audit(session,"executor","target swapped after prompt",denied)
                    session["phase"]="stopped"
                    return self._send(200,self._state(session))
                result=self.server.gate.consume(intent,payload["nonce"],payload["accept"])
                if not result["committed"] and not result.get("confirmed") and result["reason"] not in {"CANCELLED"}:
                    if not intent["pending"]: session["phase"] = "active" if intent["budget"]["steps"] > 0 else "stopped"
                    return self._send(409,{"error":result["reason"]})
                decision={"verdict":"ALLOW" if result["committed"] or result.get("confirmed") else "DENY","rules":result.get("rules",["G6"]),"reason":result.get("reason", "COMMITTED")}; audit(session,"confirmation","confirm action",decision)
                if result["committed"]:
                    # Reporting consumes no new action budget; the admitted commitment already paid it.
                    report = self.server.gate.evaluate(intent,self.server.gate.action(intent,"verify"),admitted=True)
                    audit(session,"verifier","qualified fixture report",report,"page")
                session["phase"]="complete" if result["committed"] else ("active" if intent["budget"]["steps"] > 0 else "stopped"); return self._send(200,self._state(session))
        return self._send(404,{"error":"not found"})


class PrototypeServer(ThreadingHTTPServer):
    daemon_threads=True
    def __init__(self, address): super().__init__(address, Handler); self.gate=Gate(); self.sessions={}; self.lock=threading.RLock()
def make_server(host="127.0.0.1", port=8765): return PrototypeServer((host,port))
def main():
    parser=argparse.ArgumentParser(); parser.add_argument("--port",type=int,default=8765); args=parser.parse_args()
    make_server(port=args.port).serve_forever()
if __name__=="__main__": main()
