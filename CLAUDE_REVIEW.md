# Claude review handoff — Neo / Action Lab

## Start here

- Public prototype repository: https://github.com/hemu77/neo-action-lab
- This handoff: https://github.com/hemu77/neo-action-lab/blob/main/CLAUDE_REVIEW.md
- Run instructions: https://github.com/hemu77/neo-action-lab/blob/main/README.md
- Verification evidence: https://github.com/hemu77/neo-action-lab/blob/main/VERIFICATION.md
- Architecture: https://github.com/hemu77/neo-action-lab/blob/main/submission/neo-action-security-architecture.md
- Threat model: https://github.com/hemu77/neo-action-lab/blob/main/submission/neo-action-threat-model.md
- Confirmation policy: https://github.com/hemu77/neo-action-lab/blob/main/submission/neo-action-confirmation-policy.md

**Status: Submitted. Claude review applied to docs; prototype code not reviewed by Claude.** The owner submitted the attached ZIP. Its three Markdown documents are the source of truth and remain byte-for-byte unchanged. Prototype updates continue at the same repository URL.

## What was built

A dependency-free Python backend and responsive HTML/CSS/JavaScript interface demonstrate the reservation scenario from the supplied plan. The backend owns task state, derives controlled action proposals, evaluates deterministic predicates, records decisions, and requires a one-use confirmation before creating a synthetic reservation receipt.

The user interface supports explicit intent approval, fixed-program stepping, attack probes, a rule inspector, architecture explanation, cancellation, confirmation, reset, and downloadable JSON traces. Each session uses synthetic data and isolated server state. The three submission documents are packaged at the root of `neo-action-security-architecture.zip`; source code, tests, and this handoff remain outside that ZIP.

The prototype does **not** implement Grok calls, real DOM/AX extraction, CDP interception, live Norton reputation, browser-chrome confirmation, real merchant booking, or authentication. The owner handles authentication. Production architecture requirements must not be reported as implemented merely because a fixture test passes. G7 uses explicit signed test policies; the reservation UI denies credential exposure. G8 caution and G6 unmatched-choice probes support noncommit confirmation. This is **not production-secure**.

## Run and verify

Requires Python 3.10 or newer. No dependency installation or secret is needed.

```sh
git clone https://github.com/hemu77/neo-action-lab.git
cd neo-action-lab
python -m unittest discover -s tests -v
python verify_docs.py
python server.py --port 8765
```

Open `http://127.0.0.1:8765`. Approve the intent. Probe Page phone, VIP deposit, Cross-origin beacon, and Target swap; expect G3, G2, G5, and G4 denials. Run the four normal steps; commit must pause. Cancel once and verify no receipt exists. Request a fresh action, confirm, and verify one fixture receipt. Export the trace. The server is loopback-only and intentionally rejects other Host/Origin values.

Verification is recorded in [VERIFICATION.md](VERIFICATION.md), including the 23-test pre-implementation baseline, expanded rule/trace/regression coverage, red-to-green evidence, UI checks and exact document/ZIP validation. Refer to that record for the final test count and remaining limits.

## Changes made to resolve plan contradictions

1. Scope means an exact HTTPS origin, not eTLD+1; subdomains inherit no authority.
2. Page handles retain taint. A deterministic equality witness permits a literal matched, nonsensitive choice without an extra prompt; sensitive page values still deny.
3. Mechanical classes and semantic effects are distinct. An allowed selection cannot silently add a payment effect.
4. Disclosure is bound to endpoint, audience, field, value, and purpose. Same-origin search and comments are not automatically approved recipients.
5. CDP Fetch is an interception primitive, not evidence of complete transport mediation. Production requires default-deny network enforcement and measured coverage.
6. A confirmation never overrides a denial. It expires, binds intent data, and is consumed once. The last admitted step may finish its own confirmation without acquiring a new step.
7. “Stopped” threat verdicts are conditional design assessments. Click races, credentials disclosed to compromised allowed origins, server relay, and human attention have explicit residual risk.
8. Keyboard and assistive activation remain available; rejecting Enter does not mean rejecting all accessible confirmation methods.

## Review focus

Please inspect code and tests rather than accepting this handoff's claims at face value. Prioritize:

- `gate.py`: taint/effect enforcement, denial precedence, budget admission, immutable confirmation binding, expiry, noncommit behavior, and modeled evidence versus real enforcement.
- `server.py`: Host/Origin checks, scalar validation, session isolation and bounds, concurrency, atomic consumption, reset behavior, response consistency, and export redaction.
- `static/app.js`: safe text rendering, pending/error recovery, double-click protection, accessible dialog cancellation, and stale UI behavior.
- `tests/`: boundary and adversarial coverage, including how to falsify the design rather than repeating implementation assertions.
- `verify_docs.py`: no unrelated table should satisfy the worked trace, no extra ZIP member should pass, and the bibliography must include the actual four supplied sources.
- `submission/`: cross-document consistency, realistic browser constraints, and separation between public product facts, proposed design, and implemented prototype.

Two independent review agents checked security/correctness and spec/test coverage. This pass fixed recovery admission counting, target/request endpoint binding, and forged broker/gesture authority. The parent also checked the actual diff and added secret-egress, concurrent-consumption and malformed-probe regressions. Final verification: 55 tests and all 15 document checks passed. Reviewers reported no unresolved findings in their bounded rechecks; that is not a claim that further review will find nothing.

## Expected review output

Return `APPROVE_CHECKPOINT` or `CHANGES_REQUIRED`, followed by reproducible findings ranked by severity. Each finding should cite a file/line, trigger, impact, and smallest corrective change. Separate prototype defects from production integration work deliberately excluded from this checkpoint. State remaining uncertainty even if approving.

Do not certify this as a production-secure browser. The owner reports that the challenge was submitted using the Claude-reviewed documents. Fixture tests do not establish production security.

Further Claude review should focus on the prototype code. Keep the submitted documents unchanged; report any proposed document corrections separately to the owner.
