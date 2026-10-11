# Norton Neo: confirmation policy

After all hard-denial checks pass, an action is Autonomous only when it is noncommitting or reversible, uses authorized user values or a deterministic IC-match witness for a nonsensitive page choice, stays inside approved disclosure bindings, has fresh safe reputation, and triggers no sensitive-data or special-surface rule; otherwise it requires CONFIRM.

DENY always wins. The Gate checks G1–G12 before prompting and again immediately before execution. Approval cannot legalize a page-derived sensitive value, unauthorized origin, broader purpose, or unsupported action. A changed request needs a newly minted Intent Contract in trusted chrome, not a checkbox that overrides a refusal.

## Autonomous

Each example assumes an unexpired contract, available budget, reviewed adapter, and authorized operation/effect. A reversible action can still disclose information, so G5 applies even before submission.

- Navigate to an exact HTTPS origin and approved path supplied by the IC, with no private query parameters. G1, G3, G5; T4, T7.
- Open a menu whose adapter binding has no commitment or disclosure side effect. G2, G4; T3, T6.
- Select a date or time whose canonical value exactly matches the user's IC value. The handle remains page-tainted; an equality witness satisfies G6 without bypassing G3. G3, G4, G6; T2, T13.
- Fill party size from the IC into the approved reservation field, including only authorized autosave. G3, G5; T1, T8.
- Add an explicitly requested item to a reversible cart when `cart_update` is in scope and no purchase is made. G2, G5; T2, T13.
- Apply a user-requested sort or filter on an adapter-supported view without private data in public queries. G2, G5; T4, T8.
- Dismiss a cookie banner using a reviewed rejection-of-optional-tracking action without granting permissions or widening scope. G2, G9, G12; T9, T12.

## CONFIRM

These are conditional examples, not a promise that every operation ships in the first release. Unimplemented adapters and effects still receive DENY under G2 or G9.

- Reserve or book the exact date, time, party size, and disclosed contact fields. G6; T2, T13, T15.
- Place an order or pay a user-authorized amount, only with a separately permitted payment effect and implemented adapter. G2, G6; T2, T14.
- Send a message or post a review with the user-authored body and recipient already in the IC. Page-derived outbound text remains denied. G3, G6; T8, T16.
- Enter a saved password, payment detail, or government ID through a local secret reference into an approved destination field. G7; T10, T14.
- Download a file only when the scoped download capability is implemented; show origin and destination and do not execute the file. G9; T9.
- Choose a page-recommended nonsensitive option that differs from the literal request but remains inside an expressly authorized alternative range. A changed amount or recipient is never this exception. G3, G6; T13.
- Continue an otherwise permitted action when reputation is caution, untested, stale, or unavailable. Unsafe reputation receives DENY. G8; T14, T15.

## DENY

- Change account-security settings in the first release; unsupported effects cannot be activated by confirmation. G2, G12; T11, T12.
- Send user data to an out-of-scope origin, including through images, beacons, redirects, or an unmediated transport. G1, G5; T5, T7.
- Fill a recipient, address, phone, payment amount, navigation URL, or message body taken from page text. G3; T2, T16.
- Put a reservation phone into an in-scope public search or comment field. Origin membership alone grants no disclosure permission. G5; T8.
- Grant browser permissions or use an unimplemented popup/file surface. G9; T9.
- Continue after exhausted budgets, contract expiry, invalid signature, or attempted scope widening. G10, G12; T7, T11.

## Trusted prompt and grant lifecycle

Production confirmation is browser chrome, outside page control and fullscreen. Text comes from typed fields, never model prose. Show operation, origin, audience, and exact nonsecret disclosures; mask secrets and show their account reference. Badge page-derived values “from the page.” Explain that selecting a page recommendation does not make its factual claims trusted.

Discard carried-over input during a 500 ms arming delay. Enter does not accept; use an explicit focused button with pointer, Space, or accessible assistive activation. Combine reasons for one action, not multiple future commitments. A grant expires after 30 seconds and binds intent, action/data digest, snapshot, adapter, policy, and nonce. Recheck denials, then consume it atomically once. Cancellation, stale snapshots, or changed data prevent execution. Ambiguous network outcomes require verification before any retry.

## Reviewer checklist and confirm-rate tuning

Verify every example's G and T references, denial precedence, unchanged taint, accessible cancellation, exact prompt contents, expiry, replay rejection, and absence of secrets in logs. The prototype's ordinary web dialog demonstrates the lifecycle only; it is not a protected chrome surface.

Proposed target: one commitment prompt per successful ordinary reservation and fewer than 10% of reversible matched steps prompting. Track prompts per completed task and per eligible step, plus abandonment, comprehension, unsafe approvals, and attacker success. Report a separate cohort for unfamiliar or poorly rated sites. Review weekly. Tune adapters and equality witnesses first; never relax hard denials or required commitment/credential prompts to hit a rate. These targets are proposed, not measured results.
