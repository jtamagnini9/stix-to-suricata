"""Domain name handler"""

from typing import List, Dict
from stix2suricata.handlers.base import BaseHandler
from stix2suricata.core.rule import SuricataRule


class DomainHandler(BaseHandler):
    """Handler for domain name indicators (exact match and regex MATCHES)"""

    def can_handle(self, indicator_type: str) -> bool:
        return indicator_type in ('domain', 'domain_matches')

    def handle(self, indicator: Dict, config=None) -> List[SuricataRule]:
        if indicator['type'] == 'domain_matches':
            return self._handle_matches(indicator)
        return self._handle_exact(indicator)

    def _handle_exact(self, indicator: Dict) -> List[SuricataRule]:
        """Convert exact domain indicator to Suricata DNS content rule"""
        value = indicator['value']
        metadata = indicator.get('stix_metadata', {})

        threat_type = "Suspicious domain"
        if metadata.get('labels'):
            threat_type = metadata['labels'][0]

        options = self.get_default_options(
            f"STIX IOC - {threat_type} - Domain {value}")
        options.insert(1, f'dns.query; content:"{value}"; nocase')

        return [SuricataRule(protocol="dns", options=options)]

    def _handle_matches(self, indicator: Dict) -> List[SuricataRule]:
        """Convert MATCHES domain indicator to Suricata DNS pcre rule"""
        value = indicator['value']
        metadata = indicator.get('stix_metadata', {})

        msg = metadata.get('name', 'Suspicious Domain Pattern')
        tactic = metadata.get('tactic', '')
        classtype = self._tactic_to_classtype(tactic)
        pcre = self._regex_to_pcre(value)

        options = [
            f'msg:"{msg}"',
            f'dns.query; pcre:"{pcre}"',
            f'classtype:{classtype}',
        ]

        meta_parts = []
        if metadata.get('technique'):
            meta_parts.append(f"mitre_technique {metadata['technique']}")
        if metadata.get('tactic'):
            meta_parts.append(f"mitre_tactic {metadata['tactic']}")
        if metadata.get('id'):
            meta_parts.append(f"stix_id {metadata['id']}")
        if meta_parts:
            options.append(f'metadata:{", ".join(meta_parts)}')

        return [SuricataRule(protocol="dns", options=options)]
