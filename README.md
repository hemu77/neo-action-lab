# Neo / Action Lab

A local, full-stack showcase of the submitted **Norton Neo: Injection-Resistant Action Pipeline** proposal. Approve a reservation intent, inspect G1–G12 decisions, try hostile fixture proposals, and confirm one synthetic booking.

**Submitted. Claude review applied to docs; prototype code not reviewed by Claude.** The three submitted documents and root ZIP are preserved exactly as supplied by the owner.

![Updated Neo Action Lab with a fixture reservation and rule-by-rule decision trail](design/desktop.png)

## One-command run

From this repository, with Python 3.10 or newer:

```sh
python server.py
```

Open [http://127.0.0.1:8765](http://127.0.0.1:8765). No packages, build step, API keys, or external services are required. Use this exact address: Host/Origin checks reject other hosts. Stop with Ctrl+C. Sessions, keys and receipts disappear on restart.

To obtain the source first: clone [hemu77/neo-action-lab](https://github.com/hemu77/neo-action-lab), or download and extract its source ZIP.

## Try it

1. Select date, party and time; **Approve intent**.
2. Select a probe, then **Run probe**. Page phone, VIP deposit, cross-origin beacon and target swap reproduce trace rows 11–14: G3, G2, G5 and G4 denials.
3. Additional probes demonstrate hidden/unsupported targets, same-origin public sinks, transformed values, opaque/unmediated transport, frame scope, URL/message taint, unsafe reputation, browser surfaces, budgets, redirects, recovery limits, contract tampering and revocation. Caution and unmatched choices prompt without creating a booking.
4. **Run next step** four times: navigate, select, fill, reserve. The commitment pauses at G6. Cancel once, then request it again. The prompt shows destination, endpoint, audience, purpose, data references and provenance.
5. **Confirm action** produces one synthetic receipt. **Probe target swap before execution · G4** instead changes server-owned fixture evidence, rejects the pending action and stops the task. Reset to start again.
6. **Export trace** downloads JSON without live grants. Each decision shows the decisive/highlighted rule IDs; the audit also records all checked rules. Successful stages mirror rows 1–10 of the submitted trace.

Probe branches are independent counterfactual fixtures, not a live browser continuing a denied action. Budget/expiry probes and the post-prompt target swap stop the fixture; reset creates a new task. No probe adds authority to the approved contract.

## Implemented and modeled boundaries

| Executable local model | NOT implemented |
|---|---|
| Python HTTP API, bounded isolated sessions, typed fixture proposals | Grok Planner/Reader calls or an LLM injection classifier |
| G1–G12 predicates; DENY > CONFIRM > ALLOW; all checked IDs recorded | Real DOM/AX extraction, CDP, browser input or network interception |
| Exact-origin comparisons and exact disclosure bindings | DNS resolution, transport coverage or browser sandbox enforcement |
| HMAC-signed intent projection with version/policy/revocation checks | Protected durable signing keys, authenticated chrome or remote kill-switch |
| Target/snapshot comparison, taint and equality-witness evidence | Live target instrumentation, real adapter inference or a DSL compiler |
| Contract-bound HMAC broker records, enum/envelope checks and one admitted recovery | Grok replanning or arbitrary-site recovery |
| A 500 ms arming delay and 30 s single-use grant bound to intent/action/data, snapshot, adapter and policy | Browser-chrome isolation; this is an ordinary web dialog |
| Fixture reputation ratings and scoped-surface decisions | Norton Safe Web API, real downloads/OAuth/payments or secret injection |
| Synthetic receipt and qualified site-report wording | Actual merchant booking or independent fulfillment verification |

The fixture policy override, broker issuer and single-use gesture issuer used in tests are trusted local Python APIs, never HTTP inputs. A raw broker label or fresh-gesture boolean grants no authority. Gesture records bind the signed contract and expire after 30 seconds. Reputation, provenance, equality witnesses, adapter bindings and browser evidence are supplied by fixture code. Tests cover policy responses to that evidence, not its authenticity in a real browser. G7 tests use explicitly authorized secret-reference policies; the reservation UI does not authorize credentials.

This is **not production-secure**. Authentication, deployment and browser integration are outside this prototype. The development server binds to loopback, checks Host/Origin, bounds JSON, uses HttpOnly SameSite cookies, and serves only allowlisted static files. Local processes are trusted. Do not use real credentials or contact data.

## Verify

```sh
python -m unittest discover -s tests -v
python verify_docs.py
```

Tests cover each rule's legitimate and adverse cases, the exact 14 trace verdicts/IDs, precedence, grant changes/expiry/replay, HTTP isolation and every UI probe. [Verification evidence](VERIFICATION.md) records the red-to-green work and limits. The document checker validates structure, references and ZIP bytes; it does not prove security or fully validate JSON Schema semantics.

## Review and submitted material

- [Claude handoff](CLAUDE_REVIEW.md)
- [Architecture](submission/neo-action-security-architecture.md)
- [Threat model](submission/neo-action-threat-model.md)
- [Confirmation policy](submission/neo-action-confirmation-policy.md)
- [Submitted ZIP](neo-action-security-architecture.zip)

Passing fixture tests is not evidence of open-web security or a production-ready browser.
