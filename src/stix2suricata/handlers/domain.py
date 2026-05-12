"""Domain name handler"""

from typing import List, Dict
from stix2suricata.handlers.base import BaseHandler
from stix2suricata.core.rule import SuricataRule


class DomainHandler(BaseHandler):
    """Handler for domain name indicators"""

    def can_handle(self, indicator_type: str) -> bool:
        return indicator_type == 'domain'

    def handle(self, indicator: Dict, config=None) -> List[SuricataRule]:
        """Convert domain indicator to Suricata DNS rule"""
        value = indicator['value']
        metadata = indicator.get('stix_metadata', {})

        threat_type = "Suspicious domain"
        if metadata.get('labels'):
            threat_type = metadata['labels'][0]

        options = self.get_default_options(
            f"STIX IOC - {threat_type} - Domain {value}")
        options.insert(1, f'dns.query; content:"{value}"; nocase')

        rule = SuricataRule(
            protocol="dns",
            options=options
        )

        return [rule]
