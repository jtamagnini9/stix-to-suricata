import unittest
from stix2suricata.core.parser import StixPatternParser


class TestStixPatternParserMatches(unittest.TestCase):

    def setUp(self):
        self.parser = StixPatternParser()

    def test_url_matches_type(self):
        indicators = self.parser.parse("[url:value MATCHES '.*etc/passwd.*']")
        self.assertEqual(len(indicators), 1)
        self.assertEqual(indicators[0]['type'], 'url_matches')

    def test_url_matches_value(self):
        indicators = self.parser.parse("[url:value MATCHES '.*etc/passwd.*']")
        self.assertEqual(indicators[0]['value'], '.*etc/passwd.*')

    def test_domain_matches_type(self):
        indicators = self.parser.parse("[domain-name:value MATCHES '(?i)evil\\.example\\..*']")
        self.assertEqual(len(indicators), 1)
        self.assertEqual(indicators[0]['type'], 'domain_matches')

    def test_domain_matches_value(self):
        indicators = self.parser.parse("[domain-name:value MATCHES '(?i)evil\\.example\\..*']")
        self.assertEqual(indicators[0]['value'], '(?i)evil\\.example\\..*')

    def test_process_command_line_type(self):
        indicators = self.parser.parse("[process:command_line MATCHES '(?i)nmap']")
        self.assertEqual(len(indicators), 1)
        self.assertEqual(indicators[0]['type'], 'process_command_line')

    def test_process_command_line_value(self):
        indicators = self.parser.parse("[process:command_line MATCHES '(?i)nmap']")
        self.assertEqual(indicators[0]['value'], '(?i)nmap')

    def test_exact_match_still_works(self):
        indicators = self.parser.parse("[url:value = 'http://malicious.com/payload.exe']")
        self.assertEqual(indicators[0]['type'], 'url')

    def test_pattern_field_populated(self):
        indicators = self.parser.parse("[url:value MATCHES '.*passwd.*']")
        self.assertIn('pattern', indicators[0])


if __name__ == '__main__':
    unittest.main()
