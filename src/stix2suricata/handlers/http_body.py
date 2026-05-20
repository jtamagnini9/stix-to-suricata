"""HTTP request body content handler"""

import re
from typing import List, Dict
from stix2suricata.handlers.base import BaseHandler
from stix2suricata.core.rule import SuricataRule


class HttpBodyHandler(BaseHandler):
    """Handler for artifact:payload_bin MATCHES patterns.

    Generates a single 'alert http' rule with one http.request_body content
    option per matched value. Multiple MATCHES clauses in the original STIX
    pattern are consolidated by the parser into a single 'http_body_multi'
    indicator so all content checks land in one rule.
    """

    def can_handle(self, indicator_type: str) -> bool:
        return indicator_type == 'http_body_multi'

    def handle(self, indicator: Dict, config=None) -> List[SuricataRule]:
        values = indicator.get('values', [])
        metadata = indicator.get('stix_metadata', {})

        tactic = metadata.get('tactic', '')
        classtype = self._tactic_to_classtype(tactic)
        msg = metadata.get('name', 'Suspicious HTTP body content')

        options = [
            f'msg:"{msg}"',
            'flow:to_server,established',
        ]

        for raw in values:
            content = self._strip_anchors(raw)
            content = content.replace('"', '|22|')
            options.append(f'http.request_body; content:"{content}"; nocase')

        meta_parts = []
        if metadata.get('technique'):
            meta_parts.append(f"mitre_technique {metadata['technique']}")
        if tactic:
            meta_parts.append(f"mitre_tactic {tactic}")
        if metadata.get('id'):
            meta_parts.append(f"stix_id {metadata['id']}")
        if meta_parts:
            options.append(f'metadata:{", ".join(meta_parts)}')

        options.append(f'classtype:{classtype}')

        return [SuricataRule(
            protocol='http',
            src_ip='$EXTERNAL_NET',
            dst_ip='$HOME_NET',
            options=options,
        )]

    @staticmethod
    def _strip_anchors(pattern: str) -> str:
        """Remove leading/trailing .* wildcard anchors from a STIX regex value."""
        result = re.sub(r'^(\.\*)+', '', pattern)
        result = re.sub(r'(\.\*)+$', '', result)
        return result
