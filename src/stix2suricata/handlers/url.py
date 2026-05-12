"""URL handler"""

from typing import List, Dict
from stix2suricata.handlers.base import BaseHandler
from stix2suricata.core.rule import SuricataRule


class URLHandler(BaseHandler):
    """Handler for URL indicators (exact match and regex MATCHES)"""

    def can_handle(self, indicator_type: str) -> bool:
        return indicator_type in ('url', 'url_matches')

    def handle(self, indicator: Dict, config=None) -> List[SuricataRule]:
        if indicator['type'] == 'url_matches':
            return self._handle_matches(indicator)
        return self._handle_exact(indicator)

    def _handle_exact(self, indicator: Dict) -> List[SuricataRule]:
        """Convert exact URL indicator to Suricata HTTP content rule"""
        value = indicator['value']
        metadata = indicator.get('stix_metadata', {})

        threat_type = "Suspicious URL"
        if metadata.get('labels'):
            threat_type = metadata['labels'][0]

        options = self.get_default_options(f"STIX IOC - {threat_type} - URL")

        if '://' in value:
            rest = value.split('://', 1)[1]
            if '/' in rest:
                domain = rest.split('/', 1)[0]
                path = '/' + rest.split('/', 1)[1]
            else:
                domain = rest
                path = '/'
            options.insert(1, f'http.host; content:"{domain}"; nocase')
            options.insert(2, f'http.uri; content:"{path}"; nocase')
        else:
            options.insert(1, f'http.uri; content:"{value}"; nocase')

        return [SuricataRule(protocol="http", options=options)]

    def _handle_matches(self, indicator: Dict) -> List[SuricataRule]:
        """Convert MATCHES URL indicator to Suricata HTTP pcre rule"""
        value = indicator['value']
        metadata = indicator.get('stix_metadata', {})

        msg = metadata.get('name', 'Suspicious URL Pattern')
        tactic = metadata.get('tactic', '')
        classtype = self._tactic_to_classtype(tactic)
        pcre = self._regex_to_pcre(value)

        options = [
            f'msg:"{msg}"',
            'flow:established,to_server',
            f'http.uri; pcre:"{pcre}"',
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

        return [SuricataRule(protocol="http", options=options)]
