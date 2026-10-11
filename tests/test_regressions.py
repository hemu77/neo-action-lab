import unittest
from unittest.mock import patch
from concurrent.futures import ThreadPoolExecutor

from gate import Gate


class GateRegressionTests(unittest.TestCase):
    def setUp(self):
        self.gate = Gate()
        self.intent = self.gate.mint({'party': 2, 'time': '19:00', 'date': '2026-10-16'})

    def test_changed_action_cannot_consume_existing_grant(self):
        with patch('gate.time.time', return_value=1000):
            decision = self.gate.decide(self.intent, 'commit')
        self.intent['pending']['action_record']['name'] = 'changed action'
        with patch('gate.time.time', return_value=1001):
            result = self.gate.consume(self.intent, decision['nonce'], True)
        self.assertFalse(result['committed'])
        self.assertIsNone(self.intent['reservation'])

    def test_budget_deny_does_not_skip_other_denials(self):
        self.intent['budget']['steps'] = 0
        result = self.gate.evaluate(self.intent, self.gate.action(self.intent, 'out_of_scope'))
        self.assertEqual(result['rules'], ['G1', 'G10'])

    def test_semantic_reservation_effect_requires_confirmation(self):
        action = self.gate.action(self.intent, 'commit')
        action['class'] = 'select'
        self.assertEqual(self.gate.evaluate(self.intent, action)['verdict'], 'CONFIRM')

    def test_secret_egress_cannot_hide_behind_nonsensitive_slot(self):
        for field in ('credential', 'payment_detail', 'government_id'):
            binding = dict(self.intent['disclosures'][0], field=field, value='local:secret')
            intent = self.gate.mint({'party':2,'time':'19:00','date':'2026-10-16'}, policy={'disclosures':[binding]})
            with self.subTest(field=field):
                result = self.gate.evaluate(intent, self.gate.action(intent, 'select'))
                self.assertEqual(result['verdict'], 'CONFIRM')
                self.assertIn('G7', result['rules'])

    def test_grant_data_and_execution_evidence_tampering_is_denied(self):
        for field in ('data', 'target', 'egress', 'policy'):
            self.setUp()
            with patch('gate.time.time', return_value=1000):
                decision = self.gate.decide(self.intent, 'commit')
            pending = self.intent['pending']
            if field == 'data': pending['data']['party'] = 9
            if field == 'target': pending['action_record']['current_target']['endpoint'] = '/pay'
            if field == 'egress': pending['action_record']['egress']['origin'] = 'https://evil.example'
            if field == 'policy': self.intent['revoked'] = True
            with self.subTest(field=field), patch('gate.time.time', return_value=1001):
                self.assertFalse(self.gate.consume(self.intent, decision['nonce'], True)['committed'])
                self.assertIsNone(self.intent['pending'])

    def test_admitted_recovery_consumes_the_single_replan(self):
        action = self.gate.action(self.intent, 'select')
        action['replan'] = self.gate.broker_error(self.intent, 'NOT_FOUND', ['select'], ['none'])
        first = self.gate.decide(self.intent, 'select', action)
        second = self.gate.decide(self.intent, 'select', action)
        self.assertEqual(first['verdict'], 'ALLOW')
        self.assertEqual(second['verdict'], 'DENY')
        self.assertIn('G11', second['rules'])

    def test_target_endpoint_must_match_even_an_authorized_request(self):
        binding = dict(self.intent['disclosures'][0], endpoint='/other')
        intent = self.gate.mint({'party':2,'time':'19:00','date':'2026-10-16'}, policy={'disclosures':[binding]})
        result = self.gate.evaluate(intent, self.gate.action(intent, 'fill'))
        self.assertEqual(result['verdict'], 'DENY')
        self.assertIn('G4', result['rules'])

    def test_forged_broker_label_is_not_a_recovery_authority(self):
        action = self.gate.action(self.intent, 'select')
        action['replan'] = {'source':'broker','error':'NOT_FOUND','classes':['select'],'effects':['none']}
        result = self.gate.decide(self.intent, 'select', action)
        self.assertEqual(result['verdict'], 'DENY')
        self.assertIn('G11', result['rules'])

    def test_fresh_gesture_boolean_is_not_approval(self):
        action = self.gate.action(self.intent, 'select')
        action.update(widening=True, fresh_gesture=True)
        result = self.gate.evaluate(self.intent, action)
        self.assertEqual(result['verdict'], 'DENY')
        self.assertIn('G12', result['rules'])

    def test_authenticated_fixture_gesture_is_bound_and_single_use(self):
        action = self.gate.action(self.intent, 'select')
        action.update(widening=True, fresh_gesture=True, gesture_token=self.gate.approve_widening(self.intent))
        other = self.gate.mint({'party':2,'time':'19:00','date':'2026-10-16'})
        self.assertIn('G12', self.gate.evaluate(other, action)['rules'])
        self.assertEqual(self.gate.decide(self.intent, 'select', action)['verdict'], 'ALLOW')
        self.assertIn('G12', self.gate.decide(self.intent, 'select', action)['rules'])

    def test_signed_recovery_cannot_change_contract_or_envelope(self):
        action = self.gate.action(self.intent, 'select')
        action['replan'] = self.gate.broker_error(self.intent, 'DENIED(G4)', ['select'], ['none'])
        other = self.gate.mint({'party':2,'time':'19:00','date':'2026-10-16'})
        self.assertIn('G11', self.gate.evaluate(other, action)['rules'])
        action['replan'] = self.gate.broker_error(self.intent, 'NOT_FOUND', ['select'], ['pay'])
        self.assertIn('G11', self.gate.evaluate(self.intent, action)['rules'])

    def test_grant_lifetime_and_concurrent_single_use(self):
        with patch('gate.time.time', return_value=1000):
            decision = self.gate.decide(self.intent, 'commit')
        self.assertEqual(self.intent['pending']['ready_at'], 1000.5)
        self.assertEqual(self.intent['pending']['expires_at'], 1030)
        with patch('gate.time.time', return_value=1001), ThreadPoolExecutor(max_workers=2) as executor:
            results = list(executor.map(lambda _:self.gate.consume(self.intent,decision['nonce'],True), range(2)))
        self.assertEqual(sum(result['committed'] for result in results), 1)
