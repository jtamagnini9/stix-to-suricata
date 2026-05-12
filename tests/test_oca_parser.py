import unittest
import base64
from stix2suricata.core.oca_parser import OCABundleParser

# Minimal OCA bundle: one detection + one behavior + one detects relationship
LFI_PATTERN_B64 = base64.b64encode(b"[url:value MATCHES '.*etc/passwd.*']").decode()

SAMPLE_BUNDLE = {
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
            "analytic": {
                "rule": LFI_PATTERN_B64,
                "type": "Stix Pattern"
            }
        },
        {
            "type": "relationship",
            "id": "relationship--36221057-9cc9-4d77-8543-9b2286138402",
            "relationship_type": "detects",
            "source_ref": "x-oca-detection--74a81dee-43b9-43b8-9b94-949e9b39a6e0",
            "target_ref": "x-oca-behavior--43c42191-87ee-4545-88b6-cad87e14cb1b"
        }
    ]
}

BUNDLE_NO_BEHAVIOR = {
    "type": "bundle",
    "objects": [
        {
            "type": "x-oca-detection",
            "id": "x-oca-detection--orphan",
            "name": "Orphan Detection",
            "analytic": {"rule": LFI_PATTERN_B64, "type": "Stix Pattern"}
        }
    ]
}

BUNDLE_BAD_BASE64 = {
    "type": "bundle",
    "objects": [
        {
            "type": "x-oca-detection",
            "id": "x-oca-detection--bad",
            "name": "Bad Detection",
            "analytic": {"rule": "not-valid-base64!!!", "type": "Stix Pattern"}
        }
    ]
}

BUNDLE_UNSUPPORTED_TYPE = {
    "type": "bundle",
    "objects": [
        {
            "type": "x-oca-detection",
            "id": "x-oca-detection--kql",
            "name": "KQL Detection",
            "analytic": {"rule": LFI_PATTERN_B64, "type": "KQL"}
        }
    ]
}


class TestOCABundleParser(unittest.TestCase):

    def setUp(self):
        self.parser = OCABundleParser()

    def test_returns_indicators_from_oca_bundle(self):
        indicators = self.parser.parse_bundle(SAMPLE_BUNDLE)
        self.assertEqual(len(indicators), 1)

    def test_indicator_type_is_url_matches(self):
        indicators = self.parser.parse_bundle(SAMPLE_BUNDLE)
        self.assertEqual(indicators[0]['type'], 'url_matches')

    def test_indicator_value_is_regex(self):
        indicators = self.parser.parse_bundle(SAMPLE_BUNDLE)
        self.assertEqual(indicators[0]['value'], '.*etc/passwd.*')

    def test_stix_metadata_technique(self):
        indicators = self.parser.parse_bundle(SAMPLE_BUNDLE)
        self.assertEqual(indicators[0]['stix_metadata']['technique'], 'T1190')

    def test_stix_metadata_tactic(self):
        indicators = self.parser.parse_bundle(SAMPLE_BUNDLE)
        self.assertEqual(indicators[0]['stix_metadata']['tactic'], 'TA0001')

    def test_stix_metadata_detection_id(self):
        indicators = self.parser.parse_bundle(SAMPLE_BUNDLE)
        self.assertEqual(
            indicators[0]['stix_metadata']['id'],
            'x-oca-detection--74a81dee-43b9-43b8-9b94-949e9b39a6e0'
        )

    def test_stix_metadata_name(self):
        indicators = self.parser.parse_bundle(SAMPLE_BUNDLE)
        self.assertEqual(
            indicators[0]['stix_metadata']['name'],
            'Wazuh Detection for LFI - /etc/passwd access'
        )

    def test_no_behavior_linked_still_returns_indicator(self):
        indicators = self.parser.parse_bundle(BUNDLE_NO_BEHAVIOR)
        self.assertEqual(len(indicators), 1)

    def test_no_behavior_linked_has_no_technique(self):
        indicators = self.parser.parse_bundle(BUNDLE_NO_BEHAVIOR)
        self.assertNotIn('technique', indicators[0]['stix_metadata'])

    def test_bad_base64_skips_detection(self):
        indicators = self.parser.parse_bundle(BUNDLE_BAD_BASE64)
        self.assertEqual(len(indicators), 0)

    def test_unsupported_analytic_type_skips_detection(self):
        indicators = self.parser.parse_bundle(BUNDLE_UNSUPPORTED_TYPE)
        self.assertEqual(len(indicators), 0)

    def test_empty_bundle_returns_empty_list(self):
        indicators = self.parser.parse_bundle({"type": "bundle", "objects": []})
        self.assertEqual(indicators, [])

    def test_non_oca_objects_ignored(self):
        bundle = {
            "type": "bundle",
            "objects": [
                {"type": "identity", "id": "identity--abc", "name": "Test"},
                {"type": "extension-definition", "id": "extension-definition--abc"},
            ]
        }
        indicators = self.parser.parse_bundle(bundle)
        self.assertEqual(indicators, [])


if __name__ == '__main__':
    unittest.main()
