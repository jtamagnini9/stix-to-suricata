"""URL handler"""

from typing import List, Dict
from stix2suricata.handlers.base import BaseHandler
from stix2suricata.core.rule import SuricataRule


class URLHandler(BaseHandler):
    """Handler for URL indicators"""

    def can_handle(self, indicator_type: str) -> bool:
        return indicator_type == 'url'

    def handle(self, indicator: Dict, config=None) -> List[SuricataRule]:
        """Convert URL indicator to Suricata HTTP rule"""
        value = indicator['value']
        metadata = indicator.get('stix_metadata', {})

        threat_type = "Suspicious URL"
        if metadata.get('labels'):
            threat_type = metadata['labels'][0]

        options = self.get_default_options(f"STIX IOC - {threat_type} - URL")

        # Extract domain and path from URL
        if '://' in value:
            # Split protocol and rest
            rest = value.split('://', 1)[1]

            # Extract domain (host)
            if '/' in rest:
                domain = rest.split('/', 1)[0]
                path = '/' + rest.split('/', 1)[1]
            else:
                domain = rest
                path = '/'

            # Add domain check
            options.insert(1, f'http.host; content:"{domain}"; nocase')
            # Add path check
            options.insert(2, f'http.uri; content:"{path}"; nocase')
        else:
            # Fallback if no protocol
            options.insert(1, f'http.uri; content:"{value}"; nocase')

        rule = SuricataRule(
            protocol="http",
            options=options
        )

        return [rule]
