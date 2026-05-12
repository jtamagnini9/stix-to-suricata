import unittest
import base64
from stix2suricata import StixConverter
from stix2suricata.utils.config import Config

LFI_B64 = base64.b64encode(b"[url:value MATCHES '.*etc/passwd.*']").decode()
NMAP_B64 = base64.b64encode(b"[process:command_line MATCHES '(?i)nmap']").decode()

OCA_BUNDLE = {
    "type": "bundle",
    "objects": [
        {
            "type": "x-oca-behavior",
            "id": "x-oca-behavior--43c42191-87ee-4545-88b6-cad87e14cb1b",
            "name": "LFI - /etc/passwd access",
            "description": "Local file inclusion on a vulnerable web server",
            "technique": "T1190",
            "tactic": "TA0001",
        },
        {
            "type": "x-oca-detection",
            "id": "x-oca-detection--74a81dee-43b9-43b8-9b94-949e9b39a6e0",
            "name": "Wazuh Detection for LFI - /etc/passwd access",
            "analytic": {"rule": LFI_B64, "type": "Stix Pattern"}
        },
        {
            "type": "relationship",
            "id": "relationship--aaaaaaaa",
            "relationship_type": "detects",
            "source_ref": "x-oca-detection--74a81dee-43b9-43b8-9b94-949e9b39a6e0",
            "target_ref": "x-oca-behavior--43c42191-87ee-4545-88b6-cad87e14cb1b"
        },
        {
            "type": "x-oca-behavior",
            "id": "x-oca-behavior--41548ef4-379a-46bc-8959-c6990b1727a7",
            "name": "Network Port Scan",
            "description": "Nmap scan",
            "technique": "T1046",
            "tactic": "TA0007",
        },
        {
            "type": "x-oca-detection",
            "id": "x-oca-detection--3e50100d-01a3-4cd1-9b8e-e4c655dd6486",
            "name": "Wazuh Detection for Network Port Scan",
            "analytic": {"rule": NMAP_B64, "type": "Stix Pattern"}
        },
        {
            "type": "relationship",
            "id": "relationship--bbbbbbbb",
            "relationship_type": "detects",
            "source_ref": "x-oca-detection--3e50100d-01a3-4cd1-9b8e-e4c655dd6486",
            "target_ref": "x-oca-behavior--41548ef4-379a-46bc-8959-c6990b1727a7"
        },
    ]
}


class TestConverterOCA(unittest.TestCase):

    def setUp(self):
        self.converter = StixConverter(config=Config(), starting_sid=5000000)
        self.converter.register_default_handlers()

    def test_oca_bundle_generates_rules(self):
        rules = self.converter.convert_bundle(OCA_BUNDLE)
        # LFI → 1 rule; nmap (process:command_line) → 0 rules (skipped)
        self.assertEqual(len(rules), 1)

    def test_lfi_rule_contains_pcre(self):
        rules = self.converter.convert_bundle(OCA_BUNDLE)
        self.assertIn('pcre:', rules[0])

    def test_lfi_rule_contains_etc_passwd(self):
        rules = self.converter.convert_bundle(OCA_BUNDLE)
        self.assertIn('etc\\/passwd', rules[0])

    def test_lfi_rule_contains_mitre_technique(self):
        rules = self.converter.convert_bundle(OCA_BUNDLE)
        self.assertIn('mitre_technique T1190', rules[0])

    def test_lfi_rule_contains_mitre_tactic(self):
        rules = self.converter.convert_bundle(OCA_BUNDLE)
        self.assertIn('mitre_tactic TA0001', rules[0])

    def test_lfi_rule_contains_classtype(self):
        rules = self.converter.convert_bundle(OCA_BUNDLE)
        self.assertIn('web-application-attack', rules[0])

    def test_lfi_rule_contains_rev(self):
        rules = self.converter.convert_bundle(OCA_BUNDLE)
        self.assertIn('rev:1', rules[0])

    def test_lfi_rule_contains_sid(self):
        rules = self.converter.convert_bundle(OCA_BUNDLE)
        self.assertIn('sid:5000000', rules[0])

    def test_standard_bundle_still_works(self):
        standard_bundle = {
            "type": "bundle",
            "objects": [
                {
                    "type": "indicator",
                    "id": "indicator--aaa",
                    "pattern": "[ipv4-addr:value = '1.2.3.4']",
                    "labels": ["malicious-activity"],
                    "name": "Bad IP",
                    "created": "2025-01-01T00:00:00Z",
                    "modified": "2025-01-01T00:00:00Z",
                }
            ]
        }
        rules = self.converter.convert_bundle(standard_bundle)
        self.assertEqual(len(rules), 1)
        self.assertIn('1.2.3.4', rules[0])


if __name__ == '__main__':
    unittest.main()
