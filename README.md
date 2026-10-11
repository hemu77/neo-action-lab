# Neo / Action Lab

A local, full-stack review prototype for intent-bound browser actions. Approve a reservation task, advance a fixed program, probe hostile proposals, inspect deterministic Gate decisions, and confirm one simulated commitment.

**Review checkpoint:** this repository is prepared for Claude review. Further implementation is paused until the owner returns that review and approves continuation. The same repository URL will be updated.

![Neo Action Lab showing a confirmed fixture reservation](design/desktop.png)

## Run locally

Requires Python 3.10 or later; no package installation, API key, or build step.

```sh
git clone https://github.com/hemu77/neo-action-lab.git
cd neo-action-lab
python server.py --port 8765
```

Open [http://127.0.0.1:8765](http://127.0.0.1:8765). Use this exact loopback address; the server rejects other Host and Origin values. Stop with Ctrl+C. Sessions and traces are in memory and disappear on restart.

## Try the workflow

1. Select a date, party size, and time. Click **Approve intent**.
2. Choose **Page phone**, **VIP deposit**, **Cross-origin beacon**, or **Target swap**, then **Probe attack**. Inspect G3, G2, G5, and G4 denials.
3. Click **Run next step** to navigate, select the matching time, and fill synthetic contact data.
4. The reservation commit requires **Confirm action**. Cancel to prove no reservation is created, then request a fresh action and confirm.
5. Inspect the simulated receipt and **Export trace**. Reset starts a fresh fixture.

Additional probes cover same-origin sinks, scope, reputation, browser surfaces, budgets, replanning, and scope widening. **Gate rules** and **Architecture** explain the boundary.

## What runs, and what is modeled

| Implemented in this prototype | Specified for production, not integrated |
|---|---|
| Python HTTP API and independent server sessions | Grok Planner and Reader sessions |
| Deterministic action predicates and taint checks | DOM/AX snapshots and browser input execution |
| Contract-bound fixture state and budgets | Cryptographically signed, persistent contracts |
| One-use, expiring confirmation flow | Trusted browser-chrome confirmation |
| Synthetic booking response and redacted audit export | Live merchant booking and response verification |
| Typed egress and reputation fixture decisions | CDP/network transport interception and Norton reputation |

The demo does not browse external sites or send reservations. The “review” is fixture text, and hostile scenarios construct typed proposals; they are not attacks executed against a live LLM. Snapshot, reputation, and transport evidence is fixture-supplied. The ordinary web dialog cannot provide browser-chrome isolation. Do not enter real credentials or contact data.

Authentication and production deployment are outside this checkpoint. The server binds to `127.0.0.1`, checks Host/Origin, uses HttpOnly SameSite cookies, bounds JSON, and serves a static route allowlist. This is a development server, not an Internet-facing service. Local processes remain inside its trust assumptions.

## Verify

```sh
python -m unittest discover -s tests -v
python verify_docs.py
```

The documentation checker verifies names, prose word ranges, headings, G/T references, trace branches, JSON syntax, confirmation examples, required bibliography, placeholders, overclaim phrases, and ZIP bytes. It does not prove security semantics or fully validate JSON Schema constraints.

## Review material

- [Claude review handoff](CLAUDE_REVIEW.md)
- [Security architecture](submission/neo-action-security-architecture.md)
- [Threat model](submission/neo-action-threat-model.md)
- [Confirmation policy](submission/neo-action-confirmation-policy.md)
- [Submission ZIP](neo-action-security-architecture.zip): exactly the three Markdown documents at the archive root
- [Verification evidence](VERIFICATION.md)

The docs describe a proposed production system; the table above is the narrower prototype implementation boundary. No claims of error-free behavior, open-web security, or live integration follow from passing fixture tests.
