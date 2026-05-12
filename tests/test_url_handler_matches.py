import unittest
from stix2suricata.handlers.url import URLHandler


class TestURLHandlerMatches(unittest.TestCase):

    def setUp(self):
        self.handler = URLHandler(config=None)

    def test_can_handle_url_matches(self):
        self.assertTrue(self.handler.can_handle('url_matches'))

    def test_can_handle_url_still_works(self):
        self.assertTrue(self.handler.can_handle('url'))

    def test_cannot_handle_other_types(self):
        self.assertFalse(self.handler.can_handle('ipv4'))

    def test_url_matches_generates_http_rule(self):
        indicator = {
            'type': 'url_matches',
            'value': '.*etc/passwd.*',
            'pattern': "url:value MATCHES '.*etc/passwd.*'",
            'stix_metadata': {
                'id': 'x-oca-detection--74a81dee-43b9-43b8-9b94-949e9b39a6e0',
                'name': 'LFI - /etc/passwd access',
                'technique': 'T1190',
                'tactic': 'TA0001',
            }
        }
        rules = self.handler.handle(indicator)
        self.assertEqual(len(rules), 1)
        rule_str = rules[0].to_rule(5000000)
        self.assertIn('http', rule_str)
        self.assertIn('pcre:', rule_str)
        self.assertIn('etc\\/passwd', rule_str)

    def test_url_matches_classtype_from_tactic(self):
        indicator = {
            'type': 'url_matches',
            'value': '.*etc/passwd.*',
            'pattern': "url:value MATCHES '.*etc/passwd.*'",
            'stix_metadata': {'tactic': 'TA0001', 'name': 'test', 'id': 'x-oca-detection--aaa'}
        }
        rules = self.handler.handle(indicator)
        rule_str = rules[0].to_rule(5000000)
        self.assertIn('web-application-attack', rule_str)

    def test_url_matches_includes_mitre_metadata(self):
        indicator = {
            'type': 'url_matches',
            'value': '.*etc/passwd.*',
            'pattern': "url:value MATCHES '.*etc/passwd.*'",
            'stix_metadata': {
                'id': 'x-oca-detection--74a81dee',
                'name': 'LFI test',
                'technique': 'T1190',
                'tactic': 'TA0001',
            }
        }
        rules = self.handler.handle(indicator)
        rule_str = rules[0].to_rule(5000000)
        self.assertIn('mitre_technique T1190', rule_str)
        self.assertIn('mitre_tactic TA0001', rule_str)
        self.assertIn('stix_id x-oca-detection--74a81dee', rule_str)

    def test_url_matches_no_metadata_still_generates_rule(self):
        indicator = {
            'type': 'url_matches',
            'value': '.*admin.*',
            'pattern': "url:value MATCHES '.*admin.*'",
            'stix_metadata': {}
        }
        rules = self.handler.handle(indicator)
        self.assertEqual(len(rules), 1)
        rule_str = rules[0].to_rule(5000001)
        self.assertIn('pcre:', rule_str)

    def test_url_matches_fallback_classtype_without_tactic(self):
        indicator = {
            'type': 'url_matches',
            'value': '.*test.*',
            'pattern': "url:value MATCHES '.*test.*'",
            'stix_metadata': {'name': 'test', 'id': 'x-oca-detection--bbb'}
        }
        rules = self.handler.handle(indicator)
        rule_str = rules[0].to_rule(5000002)
        self.assertIn('policy-violation', rule_str)


if __name__ == '__main__':
    unittest.main()
