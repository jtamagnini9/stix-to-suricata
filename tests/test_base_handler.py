import unittest
from stix2suricata.handlers.url import URLHandler


class TestBaseHandlerHelpers(unittest.TestCase):
    """Test helper methods inherited from BaseHandler via URLHandler."""

    def setUp(self):
        self.handler = URLHandler(config=None)

    # _regex_to_pcre tests

    def test_pcre_strips_leading_dot_star(self):
        self.assertEqual(self.handler._regex_to_pcre('.*etc/passwd.*'), '/etc\\/passwd/')

    def test_pcre_preserves_pattern_without_anchors(self):
        self.assertEqual(self.handler._regex_to_pcre('nmap'), '/nmap/')

    def test_pcre_extracts_case_insensitive_flag(self):
        self.assertEqual(self.handler._regex_to_pcre('(?i)nmap'), '/nmap/i')

    def test_pcre_flag_and_anchors_combined(self):
        self.assertEqual(self.handler._regex_to_pcre('(?i).*nmap.*'), '/nmap/i')

    def test_pcre_escapes_forward_slash(self):
        self.assertEqual(self.handler._regex_to_pcre('etc/passwd'), '/etc\\/passwd/')

    def test_pcre_only_leading_anchor(self):
        self.assertEqual(self.handler._regex_to_pcre('.*nmap'), '/nmap/')

    def test_pcre_only_trailing_anchor(self):
        self.assertEqual(self.handler._regex_to_pcre('nmap.*'), '/nmap/')

    # _tactic_to_classtype tests

    def test_ta0001_maps_to_web_application_attack(self):
        self.assertEqual(self.handler._tactic_to_classtype('TA0001'), 'web-application-attack')

    def test_ta0007_maps_to_network_scan(self):
        self.assertEqual(self.handler._tactic_to_classtype('TA0007'), 'network-scan')

    def test_ta0002_maps_to_attempted_admin(self):
        self.assertEqual(self.handler._tactic_to_classtype('TA0002'), 'attempted-admin')

    def test_ta0040_maps_to_denial_of_service(self):
        self.assertEqual(self.handler._tactic_to_classtype('TA0040'), 'denial-of-service')

    def test_unknown_tactic_falls_back_to_policy_violation(self):
        self.assertEqual(self.handler._tactic_to_classtype('TA9999'), 'policy-violation')

    def test_empty_tactic_falls_back_to_policy_violation(self):
        self.assertEqual(self.handler._tactic_to_classtype(''), 'policy-violation')


if __name__ == '__main__':
    unittest.main()
