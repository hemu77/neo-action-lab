"""Deterministic policy model; browser evidence and effects are local fixtures."""
from __future__ import annotations
import copy
import hashlib
import hmac
import ipaddress
import json
import re
import secrets
import threading
import time
from urllib.parse import urlsplit

ORIGIN = "https://luigis.example"
POLICY = "fixture-v1"
RULES = [
    ("G1", "Scope", "Exact HTTPS action, frame and destination origins; no local networks."),
    ("G2", "Class", "Mechanical class and semantic effect need a known adapter binding."),
    ("G3", "Taint-sensitive slot", "Page-derived sensitive values deny, even with a witness."),
    ("G4", "TOCTOU", "Snapshot, frame, role, label, hit-test and endpoint binding must match."),
    ("G5", "Egress", "Exact field/value/destination/endpoint/audience/purpose; parsed, mediated transport."),
    ("G6", "Commit and choice", "Commitments and unmatched nonsensitive page choices prompt."),
    ("G7", "Sensitive data", "Permitted credential, payment detail and government ID disclosures prompt."),
    ("G8", "Reputation", "Caution/untested/stale/unavailable prompt; unsafe denies."),
    ("G9", "Surfaces", "Scoped, implemented surfaces prompt; permissions always deny."),
    ("G10", "Budget", "Exhaustion, fourth redirect or expiry stops the task."),
    ("G11", "Replan source", "One broker enum recovery inside the original compiled envelope."),
    ("G12", "Widening", "Validate signature, version, revocation, policy and fresh approval."),
]
SCENARIOS = [
    ("normal", "Normal reservation", "Advance the fixed reservation program."),
    ("tainted_phone", "Page phone · G3", "Replace the local contact with a page-derived phone."),
    ("vip_deposit", "VIP deposit · G2", "Add a payment effect outside the reservation contract."),
    ("exfiltration", "Cross-origin beacon · G5", "Send the phone to evil.example."),
    ("target_swap", "Target swap · G4", "Execution revalidation sees a changed label."),
    ("hidden_target", "Hidden / covered target · G4", "A hidden or covered node is ineligible."),
    ("unsupported_root", "Uninstrumented root · G4", "A shadow/frame root has no instrumentation."),
    ("same_origin_leak", "Public same-origin sink · G5", "Put the contact in a public search."),
    ("encoded_egress", "Encoded phone payload · G5", "A transformed value differs from the authorized reference."),
    ("unmediated", "WebSocket / unmediated channel · G5", "The transport lacks interception coverage."),
    ("unparseable", "Opaque request body · G5", "The request cannot be parsed."),
    ("out_of_scope", "Out-of-scope link · G1", "Navigate to an unapproved origin."),
    ("cross_origin_frame", "Cross-origin frame · G1", "An embedded frame cannot inherit parent authority."),
    ("local_network", "Local-network destination · G1", "A local address is excluded."),
    ("page_url", "Page-derived URL · G3", "Page text supplies a navigation URL."),
    ("page_message", "Page-derived message · G3", "Reader prose attempts to become an outbound message."),
    ("unknown_binding", "Unknown adapter semantics · G2", "No reviewed binding establishes the effect."),
    ("unsafe_reputation", "Unsafe reputation · G8", "Unsafe denies; confirmation cannot bypass it."),
    ("caution", "Caution rating · G8", "An otherwise permitted action needs confirmation."),
    ("ambiguous_choice", "Unmatched page choice · G6", "No exact user-intent equality witness exists."),
    ("sensitive_data", "Unapproved credential · G5", "The reservation contract does not authorize credentials."),
    ("popup", "Popup lure · G9", "An unscoped popup cannot open."),
    ("new_tab", "New tab lure · G9", "An unscoped target cannot open."),
    ("download", "Download lure · G9", "Downloads are unimplemented in this fixture."),
    ("file_picker", "File picker lure · G9", "Local file disclosure is outside scope."),
    ("oauth", "OAuth lure · G9", "An unscoped OAuth surface cannot open."),
    ("permission", "Permission lure · G9", "Browser permission grants remain denied."),
    ("budget", "Budget exhaustion · G10", "Stop without replenishing counters."),
    ("redirect_chain", "Fourth redirect · G10", "The fourth hop stops a redirect chain."),
    ("expired", "Expired contract · G10", "Contract expiry is a hard stop."),
    ("replan", "Page-prose replan · G11", "Only broker enum errors may trigger recovery."),
    ("replan_envelope", "Recovery adds payment · G11", "A structured error cannot enlarge the program."),
    ("replan_limit", "Second recovery · G11", "At most one recovery is allowed."),
    ("widening", "Scope widening · G12", "No fresh authenticated approval supports the change."),
    ("invalid_signature", "Contract tampering · G12", "The signature no longer matches."),
    ("revoked", "Revoked intent · G12", "Revoked contracts cannot authorize actions."),
    ("stale_version", "Stale intent version · G12", "The active version differs."),
    ("policy_change", "Policy mismatch · G12", "The contract is bound to another policy."),
]
SENSITIVE = {"url", "recipient", "amount", "address", "phone", "email", "credential", "message", "message_body", "outbound_message", "payment_detail", "government_id"}
SECRET_SLOTS = {"credential", "payment_detail", "government_id"}
COMMITS = {"reserve", "pay", "order", "send", "post", "delete", "account_change"}
SURFACES = {"download", "file_picker", "popup", "new_tab", "oauth"}
BINDING_FIELDS = ("field", "value", "origin", "endpoint", "method", "audience", "purpose")
CONTRACT_FIELDS = ("id", "version", "origin", "scope_origins", "action_classes", "effects", "party", "time", "date", "phone_mask", "disclosures", "surfaces", "compiled_classes", "compiled_effects", "budget_limits", "expires_at", "policy_version")
TRACE = {
    1: ("mint", ["G12"]), 2: ("compile", ["G2", "G11"]),
    3: ("navigate", ["G1", "G8", "G10"]), 4: ("snapshot", ["G1", "G4"]),
    5: ("parse", ["G2", "G3"]), 6: ("select", ["G4", "G6"]),
    7: ("fill", ["G3", "G5"]), 8: ("reserve", ["G6"]),
    9: ("submit", ["G4", "G5", "G12"]), 10: ("verify", ["G1", "G5"]),
    11: ("tainted_phone", ["G3"]), 12: ("vip_deposit", ["G2"]),
    13: ("exfiltration", ["G5"]), 14: ("target_swap", ["G4"]),
}


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()).hexdigest()


def exact_origin(value):
    """Canonical fixture-origin check; no DNS resolution or live network inspection."""
    if not isinstance(value, str): return None
    try:
        url = urlsplit(value)
        host = url.hostname
        if url.scheme != "https" or not host or url.username or url.password or url.path not in ("", "/") or url.query or url.fragment: return None
        if host == "localhost" or host.endswith((".localhost", ".local", ".internal")) or "." not in host: return None
        try:
            if not ipaddress.ip_address(host).is_global: return None
        except ValueError:
            if not re.fullmatch(r"[a-z0-9.-]+", host) or host.endswith("."): return None
        port = url.port
        return "https://" + host + (f":{port}" if port not in (None, 443) else "")
    except ValueError: return None


class Gate:
    def __init__(self):
        # shortcut: process-local signing key; production needs protected durable keys/revocation.
        self._key = secrets.token_bytes(32)
        self._versions = {}
        self._gestures = {}
        self._lock = threading.RLock()

    def _signature(self, intent):
        return hmac.new(self._key, digest({key: intent[key] for key in CONTRACT_FIELDS}).encode(), hashlib.sha256).hexdigest()

    def mint(self, value: dict, *, policy=None) -> dict:
        """policy is a trusted fixture override, never accepted by the HTTP API."""
        party, clock, date = value.get("party"), value.get("time"), value.get("date")
        if set(value) != {"party", "time", "date"} or type(date) is not str or len(date) != 10 or type(clock) is not str or type(party) is not int or not 1 <= party <= 12 or clock not in {"18:00", "18:30", "19:00", "19:30", "20:00"}:
            raise ValueError("party must be 1-12 and time must be an offered slot")
        try: time.strptime(date, "%Y-%m-%d")
        except ValueError: raise ValueError("date must be YYYY-MM-DD")
        intent = {"id": secrets.token_urlsafe(12), "version": 1, "origin": ORIGIN, "scope_origins": [ORIGIN],
            "action_classes": ["navigate", "select", "fill", "submit_noncommit", "commit"], "effects": ["none", "reserve"],
            "party": party, "time": clock, "date": date, "phone_mask": "•••-•••-0142",
            "disclosures": [{"field": "phone", "value": "local:phone:0142", "origin": ORIGIN, "endpoint": "/reserve", "method": "POST", "audience": "merchant", "purpose": "reservation"}],
            "surfaces": [], "budget_limits": {"steps": 20, "navigations": 5}, "budget": {"steps": 20, "navigations": 5},
            "expires_at": time.time() + 900, "policy_version": POLICY, "revoked": False, "replans": 0,
            "step_index": 0, "navigations": 0, "pending": None, "reservation": None}
        if policy:
            if not set(policy) <= {"scope_origins", "action_classes", "effects", "disclosures", "surfaces"}: raise ValueError("unsupported fixture policy override")
            intent.update(copy.deepcopy(policy))
        intent["compiled_classes"] = list(intent["action_classes"])
        intent["compiled_effects"] = list(intent["effects"])
        intent["signature"] = self._signature(intent)
        self._versions[intent["id"]] = intent["version"]
        return intent

    def release(self, intent):
        if intent:
            self._versions.pop(intent["id"], None)
            self._gestures.pop(intent["id"], None)

    def broker_error(self, intent, error, classes, effects):
        """Trusted fixture broker seam; no HTTP endpoint exposes this issuer."""
        if not re.fullmatch(r"NOT_FOUND|DENIED\(G(?:[1-9]|1[0-2])\)", error): raise ValueError("invalid broker error")
        record = {"source":"broker", "error":error, "classes":list(classes), "effects":list(effects)}
        record["token"] = self._recovery_signature(intent, record)
        return record

    def _recovery_signature(self, intent, record):
        payload = {key:record[key] for key in ("source","error","classes","effects")}
        return hmac.new(self._key, (self._signature(intent) + digest(payload)).encode(), hashlib.sha256).hexdigest()

    def approve_widening(self, intent):
        """Trusted fixture gesture seam; real authenticated chrome is not implemented."""
        token = secrets.token_urlsafe(24)
        self._gestures[intent["id"]] = {"token":token,"contract":self._signature(intent),"expires_at":time.time()+30}
        return token

    def _gesture_valid(self, intent, action):
        grant = self._gestures.get(intent["id"])
        return bool(grant and action["fresh_gesture"] and action["gesture_token"] == grant["token"]
                    and grant["contract"] == self._signature(intent) and time.time() < grant["expires_at"])

    def action(self, intent: dict, scenario: str) -> dict:
        name = ["navigate", "select", "fill", "reserve"][min(intent["step_index"], 3)] if scenario == "normal" else scenario
        if name == "commit": name = "reserve"
        target = {"handle": "h:19:00", "snapshot_id": "snap-1", "frame_origin": ORIGIN, "role": "button", "label_hash": "a" * 64,
                  "visible": True, "hit_test": True, "supported": True, "binding_id": "luigis-v1", "endpoint": "/reserve"}
        egress = dict(intent["disclosures"][0]) if intent["disclosures"] else {}
        egress.update(mediated=True, parseable=True)
        a = {"name": name, "origin": ORIGIN, "frame_origin": ORIGIN, "destination": ORIGIN,
            "class": "select", "effect": "none", "taint": "user", "slot": "nonsensitive", "witness": True,
            "snapshot_ok": True, "egress_ok": True, "adapter_bound": True, "target": target, "current_target": copy.deepcopy(target), "egress": egress,
            "replan": None, "widening": False, "fresh_gesture": False, "gesture_token": None, "reputation": "safe", "surface": None,
            "surface_implemented": False, "redirect_count": 0}
        if name == "navigate": a["class"] = "navigate"
        if name in {"select", "parse", "snapshot"}: a["taint"] = "page"
        if name in {"fill", "tainted_phone", "sensitive_data"}: a.update({"class": "fill", "slot": "phone"})
        if name == "reserve": a.update({"class": "commit", "effect": "reserve"})
        if name == "tainted_phone": a["taint"] = "page"
        if name == "vip_deposit": a.update({"class": "commit", "effect": "pay"})
        if name == "exfiltration": a["egress"]["origin"] = "https://evil.example"
        if name == "same_origin_leak": a["egress"].update(endpoint="/search", audience="public", purpose="search")
        if name == "encoded_egress": a["egress"]["value"] = "encoded-contact"
        if name == "unmediated": a["egress"]["mediated"] = False
        if name == "unparseable": a["egress"]["parseable"] = False
        if name == "target_swap": a["current_target"]["label_hash"] = "b" * 64
        if name == "hidden_target": a["current_target"].update(visible=False, hit_test=False)
        if name == "unsupported_root": a["current_target"]["supported"] = False
        if name == "out_of_scope": a["origin"] = "https://evil.example"
        if name == "cross_origin_frame": a["frame_origin"] = "https://evil.example"
        if name == "local_network": a["destination"] = "https://127.0.0.1"
        if name in {"page_url", "page_message"}: a.update(taint="page", slot="url" if name == "page_url" else "message")
        if name == "unknown_binding": a["adapter_bound"] = False
        if name == "unsafe_reputation": a["reputation"] = "unsafe"
        if name == "caution": a["reputation"] = "caution"
        if name == "ambiguous_choice": a.update(taint="page", witness=False)
        if name in SURFACES | {"permission"}: a["surface"] = name
        if name == "redirect_chain": a["redirect_count"] = 4
        if name == "replan": a["replan"] = {"source": "page", "error": "user also wants payment", "classes": ["select"], "effects": ["none"]}
        if name in {"replan_envelope", "replan_limit"}: a["replan"] = self.broker_error(intent,"NOT_FOUND",["select"],["pay" if name == "replan_envelope" else "none"])
        if name == "widening": a["widening"] = True
        if name == "sensitive_data":
            a["slot"] = "credential"
            a["egress"].update(field="credential", value="local:credential")
        return a

    def probe(self, intent, scenario):
        """Fault injection uses a copy and never grants new authority."""
        projected = copy.deepcopy(intent)
        if scenario == "budget": projected["budget"]["steps"] = 0
        if scenario == "expired": projected["expires_at"] = 0; projected["signature"] = self._signature(projected)
        if scenario == "replan_limit": projected["replans"] = 1
        if scenario == "invalid_signature": projected["signature"] = "tampered"
        if scenario == "revoked": projected["revoked"] = True
        if scenario == "stale_version": projected["version"] += 1; projected["signature"] = self._signature(projected)
        if scenario == "policy_change": projected["policy_version"] = "other"; projected["signature"] = self._signature(projected)
        action = self.action(projected, scenario)
        result = self.evaluate(projected, action)
        intent["pending"] = None
        if result["verdict"] == "CONFIRM": result = self._confirm(intent, action, result)
        return action, result

    def decide(self, intent: dict, scenario: str, action: dict | None = None) -> dict:
        with self._lock:
            action = self.action(intent, scenario) if action is None else action
            decision = self.evaluate(intent, action)
            intent["pending"] = None
            if decision["verdict"] == "ALLOW" and action["replan"] is not None: intent["replans"] += 1
            if decision["verdict"] == "ALLOW" and action["widening"]: self._gestures.pop(intent["id"], None)
            return self._confirm(intent, action, decision) if decision["verdict"] == "CONFIRM" else decision

    def evaluate(self, intent: dict, a: dict, *, admitted=False) -> dict:
        try:
            if set(a) != set(self.action(intent, "select")) or a["taint"] not in {"user", "page"} or type(a["redirect_count"]) is not int or a["redirect_count"] < 0: raise ValueError("malformed action")
            for flag in ("witness", "snapshot_ok", "egress_ok", "adapter_bound", "widening", "fresh_gesture", "surface_implemented"):
                if type(a[flag]) is not bool: raise ValueError("malformed boolean")
            scopes = {exact_origin(origin) for origin in intent["scope_origins"]}
            scope_ok = None not in scopes and all(exact_origin(a[k]) in scopes and exact_origin(a[k]) is not None for k in ("origin", "frame_origin", "destination"))
            target, current, request = a["target"], a["current_target"], a["egress"]
            keys = {"handle", "snapshot_id", "frame_origin", "role", "label_hash", "visible", "hit_test", "supported", "binding_id", "endpoint"}
            target_ok = (set(target) == keys and set(current) == keys and target == current and current["endpoint"] == request.get("endpoint")
                and all(current[k] is True for k in ("visible", "hit_test", "supported"))
                and all(isinstance(current[k], str) and current[k] for k in ("handle", "snapshot_id", "binding_id", "endpoint"))
                and current["role"] in {"button", "link", "textbox", "combobox", "option", "checkbox"}
                and re.fullmatch(r"[a-f0-9]{64}", current["label_hash"]) is not None)
            scope_ok = scope_ok and exact_origin(current["frame_origin"]) in scopes
            request_ok = (set(request) == set(BINDING_FIELDS) | {"mediated", "parseable"}
                and request["mediated"] is True and request["parseable"] is True and exact_origin(request["origin"]) in scopes
                and any(all(request[k] == binding[k] for k in BINDING_FIELDS) for binding in intent["disclosures"]))
            if a["slot"] in SECRET_SLOTS: request_ok = request_ok and request["field"] == a["slot"]
            replan = a["replan"]
            replan_ok = replan is None or (set(replan) == {"source", "error", "classes", "effects", "token"}
                and replan["source"] == "broker" and re.fullmatch(r"NOT_FOUND|DENIED\(G(?:[1-9]|1[0-2])\)", replan["error"]) is not None
                and isinstance(replan["token"],str) and hmac.compare_digest(replan["token"],self._recovery_signature(intent,replan))
                and intent["replans"] < 1 and set(replan["classes"]) <= set(intent["compiled_classes"])
                and set(replan["effects"]) <= set(intent["compiled_effects"]))
            budget = intent["budget"]
            budget_ok = (all(type(budget[k]) is int and 0 <= budget[k] <= intent["budget_limits"][k] for k in ("steps", "navigations"))
                and (budget["steps"] >= 0 if admitted else budget["steps"] > 0)
                and (a["class"] != "navigate" or budget["navigations"] > 0)
                and a["redirect_count"] < 4 and time.time() < intent["expires_at"])
            identity_ok = (hmac.compare_digest(intent["signature"], self._signature(intent))
                and intent["version"] == self._versions.get(intent["id"]) and intent["revoked"] is False and intent["policy_version"] == POLICY
                and (not a["widening"] or self._gesture_valid(intent,a)))
            surface = a["surface"]
            surface_ok = surface is None or (surface in SURFACES and surface in intent["surfaces"] and a["surface_implemented"])
            checks = [scope_ok, a["class"] in intent["action_classes"] and a["effect"] in intent["effects"] and a["adapter_bound"],
                not (a["taint"] == "page" and a["slot"] in SENSITIVE), a["snapshot_ok"] and target_ok,
                a["egress_ok"] and request_ok, True, True, a["reputation"] in {"safe", "caution", "untested", "stale", "unavailable"},
                surface_ok, budget_ok, replan_ok, identity_ok]
            denied = [f"G{i}" for i, ok in enumerate(checks, 1) if not ok]
            if denied: return self._decision("DENY", denied, "POLICY_DENIED", a)
            confirmations = []
            if a["effect"] in COMMITS or a["class"] == "commit" or (a["taint"] == "page" and a["slot"] not in SENSITIVE and not a["witness"]): confirmations.append("G6")
            if a["slot"] in SECRET_SLOTS or request["field"] in SECRET_SLOTS: confirmations.append("G7")
            if a["reputation"] != "safe": confirmations.append("G8")
            if surface is not None: confirmations.append("G9")
            if confirmations: return self._decision("CONFIRM", confirmations, "ACTION_CONFIRMATION", a)
            highlights = next((rules for name, rules in TRACE.values() if name == a["name"]), ["G1", "G2", "G4", "G5"])
            return self._decision("ALLOW", highlights, "PROGRAM_STEP", a)
        except (KeyError, TypeError, ValueError, AttributeError, OverflowError):
            return self._decision("DENY", ["G2"], "MALFORMED_PROPOSAL")

    def _confirm(self, intent, action, decision):
        now = time.time()
        data = {key: intent[key] for key in ("party", "time", "date", "phone_mask")}
        data.update({"field": action["egress"]["field"], "value_reference": action["egress"]["value"], "endpoint": action["egress"]["endpoint"], "audience": action["egress"]["audience"], "purpose": action["egress"]["purpose"], "source": action["taint"]})
        pending = {"nonce": secrets.token_urlsafe(18), "action": action["name"], "origin": action["origin"], "data": data,
            "expires_at": now + 30, "ready_at": now + .5, "action_record": copy.deepcopy(action),
            "intent_digest": self._signature(intent), "action_digest": digest(action), "data_digest": digest(data), "rules": decision["rules"]}
        intent["pending"] = pending
        return {**decision, "nonce": pending["nonce"]}

    def consume(self, intent: dict, nonce: str, accept: bool) -> dict:
        with self._lock:
            pending = intent.get("pending")
            if not pending or not isinstance(nonce, str) or not hmac.compare_digest(pending["nonce"], nonce): return {"committed": False, "reason": "INVALID_OR_EXPIRED_CONFIRMATION"}
            intent["pending"] = None
            if accept is not True: return {"committed": False, "reason": "CANCELLED", "rules": pending["rules"]}
            if time.time() >= pending["expires_at"] or time.time() < pending["ready_at"]: return {"committed": False, "reason": "INVALID_OR_EXPIRED_CONFIRMATION"}
            try:
                action = pending["action_record"]
                decision = self.evaluate(intent, action, admitted=True)
                valid = (not intent.get("reservation") and pending["intent_digest"] == self._signature(intent)
                    and pending["action_digest"] == digest(action) and pending["data_digest"] == digest(pending["data"]) and decision["verdict"] != "DENY")
            except (KeyError, TypeError, ValueError): valid = False
            if not valid: return {"committed": False, "reason": "ACTION_INVALIDATED"}
            if action["replan"] is not None: intent["replans"] += 1
            if action["widening"]: self._gestures.pop(intent["id"], None)
            if action["effect"] != "reserve": return {"committed": False, "confirmed": True, "reason": "NONCOMMIT_ACTION_CONFIRMED", "rules": pending["rules"]}
            intent["reservation"] = {"id": "LUI-" + secrets.token_hex(4).upper(), "date": intent["date"], "time": intent["time"], "party": intent["party"], "report": "Luigi's fixture reports the reservation."}
            return {"committed": True, "rules": ["G4", "G5", "G12"], "reservation": intent["reservation"]}

    def trace_step(self, intent, row):
        """Evaluate each stage; row 9 requires the armed row-8 grant."""
        name, _ = TRACE[row]
        if row == 9:
            pending = intent.get("pending")
            result = self.consume(intent, pending["nonce"] if pending else "", True)
            return self._decision("ALLOW" if result["committed"] else "DENY", result.get("rules", ["G6"]), result.get("reason", "GRANT_CONSUMED"))
        return self.decide(intent, name)

    @staticmethod
    def _decision(verdict, rules, reason, action=None):
        return {"verdict": verdict, "rules": rules, "checked_rules": [f"G{i}" for i in range(1, 13)], "reason": reason,
            "nonce": None, "action_digest": digest(action) if action else None, "policy_version": POLICY}
