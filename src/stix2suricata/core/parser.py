"""STIX pattern parser"""

import re
from typing import List, Dict


class StixPatternParser:
    """Parse STIX patterns and extract indicators"""

    # Regex patterns for common STIX objects
    PATTERNS = {
        'ipv4': r"ipv4-addr:value\s*=\s*'([^']+)'",
        'ipv6': r"ipv6-addr:value\s*=\s*'([^']+)'",
        'domain': r"domain-name:value\s*=\s*'([^']+)'",
        'url': r"url:value\s*=\s*'([^']+)'",
        'network_src': r"network-traffic:src_ref\.value\s*=\s*'([^']+)'",
        'network_dst': r"network-traffic:dst_ref\.value\s*=\s*'([^']+)'",
        'network_src_port': r"network-traffic:src_port\s*=\s*(\d+)",
        'network_dst_port': r"network-traffic:dst_port\s*=\s*(\d+)",
        'network_protocol': r"network-traffic:protocols\[0\]\s*=\s*'([^']+)'",
        'file_hash_md5': r"file:hashes\.MD5\s*=\s*'([^']+)'",
        'file_hash_sha256': r"file:hashes\.'SHA-256'\s*=\s*'([^']+)'",
        'email_from': r"email-message:from_ref\.value\s*=\s*'([^']+)'",
        'email_subject': r"email-message:subject\s*=\s*'([^']+)'",
        'url_matches': r"url:value\s+MATCHES\s+'([^']+)'",
        'domain_matches': r"domain-name:value\s+MATCHES\s+'([^']+)'",
        'process_command_line': r"process:command_line\s+MATCHES\s+'([^']+)'",
        'artifact_payload_matches': r"artifact:payload_bin\s+MATCHES\s+'([^']+)'",
    }

    def parse(self, pattern: str) -> List[Dict]:
        """Parse STIX pattern and extract indicators"""
        indicators = []

        # Remove brackets and clean pattern
        pattern = pattern.strip('[]')

        # Extract all indicators
        for indicator_type, regex in self.PATTERNS.items():
            matches = re.findall(regex, pattern, re.IGNORECASE)
            for match in matches:
                indicators.append({
                    'type': indicator_type,
                    'value': match,
                    'pattern': pattern
                })

        # Consolidate all artifact:payload_bin MATCHES into one http_body_multi indicator.
        # artifact:payload_bin in IoB bundles always refers to HTTP body content, so we
        # consolidate regardless of whether an explicit HTTP context is present in the pattern.
        payload = [i for i in indicators if i['type'] == 'artifact_payload_matches']
        if payload:
            indicators = [i for i in indicators if i['type'] != 'artifact_payload_matches']
            indicators.append({
                'type': 'http_body_multi',
                'values': [i['value'] for i in payload],
                'pattern': pattern
            })

        return indicators

    def parse_bundle(self, bundle: Dict) -> List[Dict]:
        """Parse STIX bundle and extract all indicators"""
        all_indicators = []

        if 'objects' not in bundle:
            return all_indicators

        for obj in bundle['objects']:
            if obj.get('type') == 'indicator':
                pattern = obj.get('pattern')
                if pattern:
                    indicators = self.parse(pattern)

                    # Add metadata from STIX object
                    for indicator in indicators:
                        indicator['stix_metadata'] = {
                            'id': obj.get('id'),
                            'name': obj.get('name', ''),
                            'labels': obj.get('labels', []),
                            'description': obj.get('description', ''),
                            'created': obj.get('created'),
                            'modified': obj.get('modified')
                        }

                    all_indicators.extend(indicators)

        return all_indicators
