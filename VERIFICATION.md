# Verification — submitted docs and Gate prototype

Date: October 11, 2026. Status: Submitted. Claude review applied to docs; prototype code not reviewed by Claude.

## Submitted artifact integrity

Synced the three Markdown documents and root ZIP before implementation. They have not been edited since. Independent byte comparison against the owner's attached ZIP passed:

```text
BYTE MATCH neo-action-security-architecture.md SHA256 2173d1f2a54dca4564e6d7b7e0229515b278a4eb599b8236eb0d477434f4bce7
BYTE MATCH neo-action-threat-model.md SHA256 c0ab86e1c5c88bc3d243d76a6fd2d79268c0fd5d396ab3c498ec12810af85517
BYTE MATCH neo-action-confirmation-policy.md SHA256 366c32f6e1052550f8a7f3e4101abd91415bbb67aa7bb78878e4501ca957c8bc
ZIP SHA256 af0ace0c939ee816961c039a64a56834408869b892408aa000af25a21b5d8357
```

Initial checks after sync: 15/15 document checks; 23 tests passed (1.633s).

## Red → green evidence

Tests were written and executed against the old implementation before replacing Gate behavior.

| Reproduced red result | Corrected behavior |
|---|---|
| Budget denial reported only G10 instead of G1 + G10 | All applicable denials are evaluated |
| Changed pending action still committed | Full action and displayed-data digests are rechecked |
| A select action with reserve effect returned ALLOW | Semantic commitments require G6 confirmation |
| Missing structured rule fields, checked-rule reporting and trace API | Typed fixture predicates and all 14 trace rows |
| Post-prompt target-swap HTTP probe created a receipt | Changed execution evidence denies G4 and consumes the grant |
| Authorized secret egress hidden behind nonsensitive slot returned ALLOW | G7 also inspects the outgoing field type |
| A second admitted recovery returned ALLOW | Admission atomically consumes the one-replan allowance |
| Authorized request endpoint differed from target endpoint | G4 enforces the target/request binding |
| Raw broker label and fresh-gesture boolean returned ALLOW | Contract-bound broker HMAC and one-use gesture records |
| Malformed probe object disconnected HTTP request | Invalid probe types return HTTP 400 |

The first focused run was 3 tests / 3 failures. The implementation helper separately wrote the rule and trace suites and observed red results. Subsequent fixes used targeted failing regressions before implementation. Final results are below.

## Final unit and integration output

Command: `python -m unittest discover -s tests -v` (invoked through RTK, Python UTF-8 mode on Windows).

```text
test_complete_fixture_and_supplied_references_pass (test_docs.DocumentationTests.test_complete_fixture_and_supplied_references_pass) ... ok
test_duplicate_zip_and_extra_file_are_rejected (test_docs.DocumentationTests.test_duplicate_zip_and_extra_file_are_rejected) ... ok
test_empty_docs_and_invalid_json_are_rejected (test_docs.DocumentationTests.test_empty_docs_and_invalid_json_are_rejected) ... ok
test_overclaim_word_boundaries_and_unknown_references (test_docs.DocumentationTests.test_overclaim_word_boundaries_and_unknown_references) ... ok
test_tables_outside_required_section_do_not_satisfy_checks (test_docs.DocumentationTests.test_tables_outside_required_section_do_not_satisfy_checks) ... ok
test_boundary_inputs_fail_with_validation_error (test_gate.GateTests.test_boundary_inputs_fail_with_validation_error) ... ok
test_budget_and_expiry_deny (test_gate.GateTests.test_budget_and_expiry_deny) ... ok
test_cancel_is_available_before_arming_and_after_expiry (test_gate.GateTests.test_cancel_is_available_before_arming_and_after_expiry) ... ok
test_changed_contract_or_expired_intent_cannot_commit (test_gate.GateTests.test_changed_contract_or_expired_intent_cannot_commit) ... ok
test_commit_requires_single_use_confirm (test_gate.GateTests.test_commit_requires_single_use_confirm) ... ok
test_deny_precedence_and_all_rules (test_gate.GateTests.test_deny_precedence_and_all_rules) ... ok
test_evaluation_is_pure_and_denial_overrides_confirmation (test_gate.GateTests.test_evaluation_is_pure_and_denial_overrides_confirmation) ... ok
test_grant_expiry_boundary_and_early_accept (test_gate.GateTests.test_grant_expiry_boundary_and_early_accept) ... ok
test_last_admitted_step_can_confirm (test_gate.GateTests.test_last_admitted_step_can_confirm) ... ok
test_navigation_budget_and_noncommit_confirmation (test_gate.GateTests.test_navigation_budget_and_noncommit_confirmation) ... ok
test_page_taint_denies_sensitive_slot (test_gate.GateTests.test_page_taint_denies_sensitive_slot) ... ok
test_sensitive_data_requires_confirmation (test_gate.GateTests.test_sensitive_data_requires_confirmation) ... ok
test_admitted_recovery_consumes_the_single_replan (test_regressions.GateRegressionTests.test_admitted_recovery_consumes_the_single_replan) ... ok
test_authenticated_fixture_gesture_is_bound_and_single_use (test_regressions.GateRegressionTests.test_authenticated_fixture_gesture_is_bound_and_single_use) ... ok
test_budget_deny_does_not_skip_other_denials (test_regressions.GateRegressionTests.test_budget_deny_does_not_skip_other_denials) ... ok
test_changed_action_cannot_consume_existing_grant (test_regressions.GateRegressionTests.test_changed_action_cannot_consume_existing_grant) ... ok
test_forged_broker_label_is_not_a_recovery_authority (test_regressions.GateRegressionTests.test_forged_broker_label_is_not_a_recovery_authority) ... ok
test_fresh_gesture_boolean_is_not_approval (test_regressions.GateRegressionTests.test_fresh_gesture_boolean_is_not_approval) ... ok
test_grant_data_and_execution_evidence_tampering_is_denied (test_regressions.GateRegressionTests.test_grant_data_and_execution_evidence_tampering_is_denied) ... ok
test_grant_lifetime_and_concurrent_single_use (test_regressions.GateRegressionTests.test_grant_lifetime_and_concurrent_single_use) ... ok
test_secret_egress_cannot_hide_behind_nonsensitive_slot (test_regressions.GateRegressionTests.test_secret_egress_cannot_hide_behind_nonsensitive_slot) ... ok
test_semantic_reservation_effect_requires_confirmation (test_regressions.GateRegressionTests.test_semantic_reservation_effect_requires_confirmation) ... ok
test_signed_recovery_cannot_change_contract_or_envelope (test_regressions.GateRegressionTests.test_signed_recovery_cannot_change_contract_or_envelope) ... ok
test_target_endpoint_must_match_even_an_authorized_request (test_regressions.GateRegressionTests.test_target_endpoint_must_match_even_an_authorized_request) ... ok
test_combined_denials_and_boundaries (test_rules.RuleContractTests.test_combined_denials_and_boundaries) ... ok
test_confirmation_rules_and_positive_surface (test_rules.RuleContractTests.test_confirmation_rules_and_positive_surface) ... ok
test_each_rule_has_a_negative_case (test_rules.RuleContractTests.test_each_rule_has_a_negative_case) ... ok
test_g10_step_nav_redirect_and_expiry_boundaries (test_rules.RuleContractTests.test_g10_step_nav_redirect_and_expiry_boundaries) ... ok
test_g11_requires_broker_enum_same_envelope_and_one_replan (test_rules.RuleContractTests.test_g11_requires_broker_enum_same_envelope_and_one_replan) ... ok
test_g12_signature_version_policy_revocation_and_fresh_gesture (test_rules.RuleContractTests.test_g12_signature_version_policy_revocation_and_fresh_gesture) ... ok
test_g1_exact_https_scope_rejects_cross_origin_subdomain_http_and_private (test_rules.RuleContractTests.test_g1_exact_https_scope_rejects_cross_origin_subdomain_http_and_private) ... ok
test_g2_rejects_unknown_class_effect_and_unbound_adapter (test_rules.RuleContractTests.test_g2_rejects_unknown_class_effect_and_unbound_adapter) ... ok
test_g3_rejects_every_sensitive_page_slot_even_with_witness (test_rules.RuleContractTests.test_g3_rejects_every_sensitive_page_slot_even_with_witness) ... ok
test_g4_compares_each_target_field_and_rejects_ineligible_targets (test_rules.RuleContractTests.test_g4_compares_each_target_field_and_rejects_ineligible_targets) ... ok
test_g5_binds_every_disclosure_dimension_and_transport (test_rules.RuleContractTests.test_g5_binds_every_disclosure_dimension_and_transport) ... ok
test_g6_confirms_each_commit_effect_and_unwitnessed_page_choice (test_rules.RuleContractTests.test_g6_confirms_each_commit_effect_and_unwitnessed_page_choice) ... ok
test_g7_requires_explicit_signed_credential_disclosure_and_never_page_credential (test_rules.RuleContractTests.test_g7_requires_explicit_signed_credential_disclosure_and_never_page_credential) ... ok
test_g8_all_ratings (test_rules.RuleContractTests.test_g8_all_ratings) ... ok
test_g9_surfaces_default_deny_scoped_confirm_and_permissions_deny (test_rules.RuleContractTests.test_g9_surfaces_default_deny_scoped_confirm_and_permissions_deny) ... ok
test_malformed_fails_closed_and_confirmation_binding (test_rules.RuleContractTests.test_malformed_fails_closed_and_confirmation_binding) ... ok
test_positive_baseline_checks_all_rules (test_rules.RuleContractTests.test_positive_baseline_checks_all_rules) ... ok
test_all_ui_probes_reach_the_expected_gate_rule (test_server.ServerTests.test_all_ui_probes_reach_the_expected_gate_rule) ... ok
test_bounded_sessions_expire_and_reject_spoofed_host (test_server.ServerTests.test_bounded_sessions_expire_and_reject_spoofed_host) ... ok
test_budget_probe_stops_until_reset_and_exports_no_nonce (test_server.ServerTests.test_budget_probe_stops_until_reset_and_exports_no_nonce) ... ok
test_isolation_replay_and_static_security_headers (test_server.ServerTests.test_isolation_replay_and_static_security_headers) ... ok
test_last_step_commit_is_admitted_once_via_http (test_server.ServerTests.test_last_step_commit_is_admitted_once_via_http) ... ok
test_malformed_types_and_missing_session_are_rejected (test_server.ServerTests.test_malformed_types_and_missing_session_are_rejected) ... ok
test_noncommit_confirmation_and_postprompt_target_swap (test_server.ServerTests.test_noncommit_confirmation_and_postprompt_target_swap) ... ok
test_rejects_malformed_and_hostile_mutations (test_server.ServerTests.test_rejects_malformed_and_hostile_mutations) ... ok
test_exact_fourteen_row_trace (test_trace.WorkedTraceTests.test_exact_fourteen_row_trace) ... ok

----------------------------------------------------------------------
Ran 55 tests in 1.651s

OK
```

Rule tests pair an allowed baseline with adverse cases; G6–G9 additionally test permitted confirmation paths. The trace test checks all 14 exact verdict/rule-ID tuples; row 9 consumes an actual row-8 grant with a mocked clock. Independent hostile rows run no external effects.

Additional tests exercise all 37 UI probe routes, cancellation, altered action/data/target/request/policy, expiry, arming, concurrent grant consumption, single-use recovery/gesture records, malformed HTTP, session isolation and export redaction.

## Final document verification output

Command: `python verify_docs.py`.

```text
PASS submission files: found: neo-action-confirmation-policy.md, neo-action-security-architecture.md, neo-action-threat-model.md
PASS word count: neo-action-security-architecture.md: 2990 (need 1800-3500)
PASS word count: neo-action-threat-model.md: 1182 (need 450-1500)
PASS word count: neo-action-confirmation-policy.md: 840 (need 500-1000)
PASS architecture headings: all 11 present
PASS G1-G12 rule table: rows: [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]
PASS decision trace: numbered rows=14, DENY rules=[2, 3, 4, 5]
PASS JSON schemas: parsed
PASS threat table: T rows=16, Accepted=3, rules valid=True
PASS cross references: unknown G=[], unknown T=[]
PASS confirmation policy examples: Autonomous=7, CONFIRM=7, DENY=6; every example needs G and T
PASS supplied reference titles: all four cited
PASS no overclaims: clear
PASS no placeholders: clear
PASS ZIP contents and bytes: members: neo-action-security-architecture.md, neo-action-threat-model.md, neo-action-confirmation-policy.md; bytes match=True
```

## UI and reviews

Codex in-app browser checks observed:

- Encoded egress denied G5; post-prompt target swap denied G4, created no receipt and stopped the fixture.
- Cancellation created no receipt; a fresh reservation request could be confirmed.
- Enter left the dialog open; focused Space activated confirmation and produced one synthetic receipt.
- Normal flow produced ten decisions corresponding to the successful architecture trace.
- Export downloaded JSON. No browser console errors were observed.
- Refreshed desktop and mobile screenshots are in `design/`. Mobile measured client width and scroll width both 375 CSS pixels (no horizontal overflow). Temporary viewport overrides were reset.

One implementation helper authored tests. Two read-only reviewers covered spec/test/maintainability and security/correctness. Review findings were fixed and rechecked. The Codex Security diff workflow completed scan `9eba37b3-fea9-4e5f-a52b-d2a68035a7e2` with no unresolved findings in its bounded scope. The security reviewer rechecked 54 tests; the parent subsequently added the concurrent grant test and malformed-probe regression and ran the final 55-test suite.

The spec reviewer used current source and immutable submitted docs after its Git-diff invocation used the wrong directory; the parent reviewed the actual repository diff. These are bounded reviews, not proof that all defects have been found. `git diff --check` passed.

## Limits

No real Grok, DOM/AX extraction, CDP/network interception, Norton Safe Web, browser-chrome authentication, merchant booking, production deployment or external penetration test was performed. Instrumentation, adapter semantics, taint/witness evidence and issuer events remain fixtures. Signing keys and all state are process-local. The document verifier checks structure and byte equality, not security semantics or full JSON Schema validity. This prototype is not production-secure.
