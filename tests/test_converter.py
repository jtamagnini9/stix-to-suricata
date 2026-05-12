"""Tests for converter"""

import unittest
import logging
from stix2suricata import StixConverter
from stix2suricata.utils.config import Config


class TestConverter(unittest.TestCase):
    """Test converter functionality"""

    def setUp(self):
        self.config = Config()
        self.converter = StixConverter(
            config=self.config, starting_sid=9000000)
        self.converter.register_default_handlers()

    def test_ipv4_conversion(self):
        """Test IPv4 indicator conversion"""
        pattern = "[ipv4-addr:value = '192.168.1.100']"
        rules = self.converter.convert_pattern(pattern)

        self.assertEqual(len(rules), 1)
        logging.info('Ipv4 rules: %s', rules)
        self.assertIn('192.168.1.100', rules[0])
        self.assertIn('sid:9000000', rules[0])

    def test_domain_conversion(self):
        """Test domain indicator conversion"""
        pattern = "[domain-name:value = 'evil.example.com']"
        rules = self.converter.convert_pattern(pattern)

        self.assertEqual(len(rules), 1)
        logging.info('Domain rules: %s', rules)
        self.assertIn('evil.example.com', rules[0])
        self.assertIn('dns', rules[0])

    def test_url_conversion(self):
        """Test URL indicator conversion"""
        pattern = "[url:value = 'http://malicious.com/payload.exe']"
        rules = self.converter.convert_pattern(pattern)
        logging.info('URL rules: %s', rules)
        self.assertEqual(len(rules), 1)
        self.assertIn('http', rules[0])


if __name__ == '__main__':
    unittest.main()
