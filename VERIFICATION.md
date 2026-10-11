# Verification record

Review checkpoint prepared on 2026-10-11. **READY for local prototype review; NOT READY for production browser security.**

## Automated evidence

`python -m unittest discover -s tests -v` — 23 tests passed.

Coverage includes policy denials, page taint, confirmation precedence and purity, arming/expiry boundaries, cancellation, nonce replay, changed intent values, last-step confirmation through Gate and HTTP, noncommit confirmation, exhausted navigation/step budgets, malformed types, Host/Origin rejection, session isolation/cap/expiry, static route rejection, export token exclusion, and document-checker mutation cases.

`python verify_docs.py` — all 15 checks passed, including exact ZIP membership and byte equality with source documents.

| Document | Prose words | Required range |
|---|---:|---:|
| Architecture | 2,709 | 1,800–3,500 |
| Threat model | 1,165 | 450–1,500 |
| Confirmation policy | 828 | 500–1,000 |

The count excludes fenced JSON/Mermaid code and uses the checker's documented word tokenizer. It is not a rendered page-count measurement. The architecture defines G1–G12 and a 14-row trace. The threat model has T1–T16, including three Accepted risks. The policy has seven Autonomous, seven CONFIRM, and six DENY examples. JSON fences parse; full Draft 2020-12 schema/instance validation was not run.

Acceptance checks were written before the submission files existed. The initial run exited nonzero with missing-document and missing-ZIP failures. That expected red state was followed by document generation and green checks. No evidence from a live Grok/browser-security integration is implied.

## Browser evidence

Codex in-app browser, no Playwright browser-process fallback:

| Journey | Observed result |
|---|---|
| Approve intent and run fixed program | Navigate, select, fill, then G6 confirmation |
| Four hostile proposals | Page phone G3; VIP deposit G2; cross-origin beacon G5; target swap G4: DENY |
| Cancel confirmation | Dialog closes; no reservation receipt; fresh action can be requested |
| Confirm once | One synthetic site-reported receipt; stepping disabled after completion |
| Export trace | JSON download completed; API tests exclude nonce/action-record fields |
| Responsive layout | Desktop 1440×1000 viewport; mobile 390×844; document scroll width equaled mobile viewport width |
| Console | No error entries observed in tested workflow |

The hostile-probe/cancel browser checks preceded final backend hardening. The final backend was restarted and the full happy path through confirmation, receipt, and export was rerun. Regression tests separately cover all fixes. This distinction matters: browser observations are bounded samples, not a reliability estimate.

Screenshots: [desktop](design/desktop.png), [mobile](design/mobile.png), [concept](design/concept.png). These are synthetic fixture states. Backend startup and external APIs were not tested on another machine or operating system.

## Visual review

The built-in image-generation tool produced the primary concept. The final interface and concept were inspected with `view_image`; the browser screenshots were captured through the in-app browser. Compared five concrete areas: forest navigation rail, paper/white/lime palette, two-column task/Gate layout, serif restaurant heading versus sans-serif interface type, and the compact decision table. Mobile collapses to one column without horizontal page overflow.

The primary copy matches the concept. Intentional functional additions are the reset control after approval, contract budget, fixture-boundary disclosure, dynamic receipt, populated audit rows, and confirmation dialog. “Select a time” became “Available times” because the fixture slots are display-only; task time is edited in the intent form. Native date formatting follows the host locale. Simple Unicode navigation symbols replace illustrative concept icons. These are implementation choices, not pixel-perfect identity claims.

## Independent reviews and resolved findings

One implementation agent built acceptance checks and the backend. Two separate read-only agents reviewed the checkpoint:

| Review lane | Finding | Resolution |
|---|---|---|
| Correctness/security | Last remaining step could request confirmation but fail consumption | Preserve admission for that same action; Gate + HTTP regressions |
| Correctness/security | Unbounded cookie-less local sessions | Cap 64 sessions, 30-minute idle expiry, cross-site read rejection |
| Spec/test coverage | Checker required substituted source titles | Require the owner's original four titles across documents |
| Spec/test coverage | Unrelated tables could satisfy rule/trace checks | Bound checks to their named sections; mutation regression |
| Spec/test coverage | Missing changed-intent regression | Date/time/contact-reference/expiry mutation cases |

Both reviewers reported no unresolved findings after their bounded recheck. Parent additionally aligned normal selection provenance with page taint and bound the displayed contact reference in the confirmation digest; the complete 23-test suite passed afterward.

## Limitations

No production authentication, Grok, live merchant, Safe Web API, actual DOM/AX snapshot, CDP/network interception, protected chrome UI, persistent audit storage, remote kill-switch, or attack-success benchmark is implemented or verified. The Gate trusts fixture evidence such as snapshot and egress flags; a production adapter must derive those from enforcement points. The standard-library server is for loopback development only. Sessions are transient; audit retention is capped at 200 entries per session.

No full challenge brief, authenticated competition workflow, external deployment, or submission was tested. Claude review and owner approval are the next gate before further implementation.
