import unittest
from stix2suricata.handlers.domain import DomainHandler


class TestDomainHandlerMatches(unittest.TestCase):

    def setUp(self):
        self.handler = DomainHandler(config=None)

    def test_can_handle_domain_matches(self):
        self.assertTrue(self.handler.can_handle('domain_matches'))

    def test_can_handle_domain_still_works(self):
        self.assertTrue(self.handler.can_handle('domain'))

    def test_cannot_handle_url(self):
        self.assertFalse(self.handler.can_handle('url'))

    def test_domain_matches_generates_dns_rule(self):
        indicator = {
            'type': 'domain_matches',
            'value': '(?i)evil\\.example\\..*',
            'pattern': "domain-name:value MATCHES '(?i)evil\\.example\\..*'",
            'stix_metadata': {
                'id': 'x-oca-detection--aabbccdd',
                'name': 'Suspicious Domain Pattern',
                'technique': 'T1071',
                'tactic': 'TA0011',
            }
        }
        rules = self.handler.handle(indicator)
        self.assertEqual(len(rules), 1)
        rule_str = rules[0].to_rule(5000010)
        self.assertIn('dns', rule_str)
        self.assertIn('pcre:', rule_str)

    def test_domain_matches_case_insensitive_flag(self):
        indicator = {
            'type': 'domain_matches',
            'value': '(?i)evil.*',
            'pattern': "domain-name:value MATCHES '(?i)evil.*'",
            'stix_metadata': {'name': 'test', 'id': 'x-oca-detection--test', 'tactic': ''}
        }
        rules = self.handler.handle(indicator)
        rule_str = rules[0].to_rule(5000011)
        self.assertIn('/i', rule_str)

    def test_domain_matches_includes_mitre_metadata(self):
        indicator = {
            'type': 'domain_matches',
            'value': '.*evil.*',
            'pattern': "domain-name:value MATCHES '.*evil.*'",
            'stix_metadata': {
                'id': 'x-oca-detection--xyz',
                'name': 'Bad domain',
                'technique': 'T1071',
                'tactic': 'TA0011',
            }
        }
        rules = self.handler.handle(indicator)
        rule_str = rules[0].to_rule(5000012)
        self.assertIn('mitre_technique T1071', rule_str)
        self.assertIn('mitre_tactic TA0011', rule_str)

    def test_domain_matches_fallback_classtype(self):
        indicator = {
            'type': 'domain_matches',
            'value': '.*evil.*',
            'pattern': "domain-name:value MATCHES '.*evil.*'",
            'stix_metadata': {'name': 'test', 'id': 'x-oca-detection--zzz'}
        }
        rules = self.handler.handle(indicator)
        rule_str = rules[0].to_rule(5000013)
        self.assertIn('policy-violation', rule_str)


if __name__ == '__main__':
    unittest.main()
