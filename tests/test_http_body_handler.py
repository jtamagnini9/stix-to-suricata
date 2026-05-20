"""Tests for HTTP body pattern parsing and rule generation"""
import unittest
import base64
from stix2suricata.core.parser import StixPatternParser
from stix2suricata.handlers.http_body import HttpBodyHandler
from stix2suricata import StixConverter
from stix2suricata.utils.config import Config


XXE_PATTERN = (
    "[\n"
    "  network-traffic:protocols[0] = 'http'\n"
    "  AND network-traffic:extensions.'http-request-ext'.request_method = 'POST'\n"
    "  AND artifact:payload_bin MATCHES '.*<!ENTITY.*'\n"
    "  AND artifact:payload_bin MATCHES '.*SYSTEM.*'\n"
    "]"
)

XXE_B64 = base64.b64encode(XXE_PATTERN.encode()).decode()

OCA_BUNDLE = {
    "type": "bundle",
    "objects": [
        {
            "type": "x-oca-behavior",
            "id": "x-oca-behavior--xxe00001-0000-4000-a000-000000000001",
            "name": "Initial Access: Exploit Public-Facing Application",
            "description": "XXE injection via HTTP POST",
            "technique": "T1190",
            "tactic": "TA0001",
        },
        {
            "type": "x-oca-detection",
            "id": "x-oca-detection--xxe00001-0000-4000-a000-000000000002",
            "name": "Wazuh Detection for Initial Access: Exploit Public-Facing Application",
            "analytic": {"rule": XXE_B64, "type": "Stix Pattern"},
        },
        {
            "type": "relationship",
            "id": "relationship--xxe00001-0000-4000-a000-000000000003",
            "relationship_type": "detects",
            "source_ref": "x-oca-detection--xxe00001-0000-4000-a000-000000000002",
            "target_ref": "x-oca-behavior--xxe00001-0000-4000-a000-000000000001",
        },
    ],
}


class TestParserHttpBody(unittest.TestCase):

    def setUp(self):
        self.parser = StixPatternParser()

    def test_single_payload_match_produces_http_body_multi(self):
        pattern = "[network-traffic:protocols[0] = 'http' AND artifact:payload_bin MATCHES '.*<!ENTITY.*']"
        indicators = self.parser.parse(pattern)
        types = [i['type'] for i in indicators]
        self.assertIn('http_body_multi', types)

    def test_two_payload_matches_consolidated_into_one_indicator(self):
        indicators = self.parser.parse(XXE_PATTERN)
        body_indicators = [i for i in indicators if i['type'] == 'http_body_multi']
        self.assertEqual(len(body_indicators), 1)

    def test_consolidated_indicator_contains_both_values(self):
        indicators = self.parser.parse(XXE_PATTERN)
        body = next(i for i in indicators if i['type'] == 'http_body_multi')
        self.assertIn('.*<!ENTITY.*', body['values'])
        self.assertIn('.*SYSTEM.*', body['values'])


class TestHttpBodyHandler(unittest.TestCase):

    def setUp(self):
        self.handler = HttpBodyHandler(config=None)

    def test_can_handle_http_body_multi(self):
        self.assertTrue(self.handler.can_handle('http_body_multi'))

    def test_cannot_handle_ipv4(self):
        self.assertFalse(self.handler.can_handle('ipv4'))

    def test_generates_one_rule(self):
        indicator = {
            'type': 'http_body_multi',
            'values': ['.*<!ENTITY.*', '.*SYSTEM.*'],
            'stix_metadata': {'name': 'XXE detection', 'tactic': 'TA0001'},
        }
        rules = self.handler.handle(indicator)
        self.assertEqual(len(rules), 1)

    def test_rule_protocol_is_http(self):
        indicator = {
            'type': 'http_body_multi',
            'values': ['.*<!ENTITY.*'],
            'stix_metadata': {'name': 'XXE', 'tactic': 'TA0001'},
        }
        rules = self.handler.handle(indicator)
        self.assertEqual(rules[0].protocol, 'http')

    def test_rule_options_contain_entity_content(self):
        indicator = {
            'type': 'http_body_multi',
            'values': ['.*<!ENTITY.*', '.*SYSTEM.*'],
            'stix_metadata': {'name': 'XXE', 'tactic': 'TA0001'},
        }
        rules = self.handler.handle(indicator)
        rule_str = rules[0].to_rule(1000005)
        self.assertIn('content:"<!ENTITY"', rule_str)
        self.assertIn('content:"SYSTEM"', rule_str)
        self.assertIn('nocase', rule_str)

    def test_rule_classtype_web_application_attack_for_ta0001(self):
        indicator = {
            'type': 'http_body_multi',
            'values': ['.*<!ENTITY.*'],
            'stix_metadata': {'name': 'XXE', 'tactic': 'TA0001'},
        }
        rules = self.handler.handle(indicator)
        rule_str = rules[0].to_rule(1000005)
        self.assertIn('classtype:web-application-attack', rule_str)


class TestConverterOCAWithHttpBody(unittest.TestCase):

    def setUp(self):
        self.converter = StixConverter(config=Config(), starting_sid=1000005)
        self.converter.register_default_handlers()

    def test_xxe_oca_bundle_generates_rule(self):
        rules = self.converter.convert_bundle(OCA_BUNDLE)
        self.assertTrue(len(rules) > 0)

    def test_xxe_rule_contains_entity_content(self):
        rules = self.converter.convert_bundle(OCA_BUNDLE)
        combined = '\n'.join(rules)
        self.assertIn('<!ENTITY', combined)
        self.assertIn('SYSTEM', combined)

    def test_xxe_rule_is_http_alert(self):
        rules = self.converter.convert_bundle(OCA_BUNDLE)
        self.assertTrue(any(r.startswith('alert http') for r in rules))


if __name__ == '__main__':
    unittest.main()
