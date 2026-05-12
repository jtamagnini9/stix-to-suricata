import unittest
from stix2suricata.core.rule import SuricataRule


class TestSuricataRule(unittest.TestCase):

    def test_to_rule_contains_rev1(self):
        rule = SuricataRule(options=['msg:"test"'])
        result = rule.to_rule(1000)
        self.assertIn('rev:1', result)

    def test_to_rule_empty_options_contains_rev1(self):
        rule = SuricataRule()
        result = rule.to_rule(1001)
        self.assertIn('rev:1', result)
        self.assertIn('sid:1001', result)

    def test_to_rule_rev1_after_sid(self):
        rule = SuricataRule(options=['msg:"test"'])
        result = rule.to_rule(1002)
        sid_pos = result.index('sid:1002')
        rev_pos = result.index('rev:1')
        self.assertGreater(rev_pos, sid_pos)


if __name__ == '__main__':
    unittest.main()
