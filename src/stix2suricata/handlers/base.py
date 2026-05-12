"""Base handler class"""

import re
from abc import ABC, abstractmethod
from typing import List, Dict
from stix2suricata.core.rule import SuricataRule


class BaseHandler(ABC):
    """Base class for indicator handlers"""

    TACTIC_CLASSTYPE = {
        'TA0001': 'web-application-attack',
        'TA0007': 'network-scan',
        'TA0002': 'attempted-admin',
        'TA0040': 'denial-of-service',
    }

    def __init__(self, config=None):
        self.config = config

    @abstractmethod
    def can_handle(self, indicator_type: str) -> bool:
        """Check if this handler can process the indicator type"""
        pass

    @abstractmethod
    def handle(self, indicator: Dict, config=None) -> List[SuricataRule]:
        """Convert indicator to Suricata rules"""
        pass

    def get_default_options(self, message: str) -> List[str]:
        """Get default rule options"""
        priority = self.config.get(
            'suricata.default_priority', 2) if self.config else 2
        classtype = self.config.get(
            'suricata.default_classtype', 'trojan-activity') if self.config else 'trojan-activity'

        return [
            f'msg:"{message}"',
            f'classtype:{classtype}',
            f'priority:{priority}'
        ]

    def _regex_to_pcre(self, pattern: str) -> str:
        """Convert a STIX regex string to a Suricata pcre string.

        Handles (?i) inline flag, leading/trailing .* anchors, and / escaping.
        Example: '.*etc/passwd.*' -> '/etc\\/passwd/'
        Example: '(?i)nmap'       -> '/nmap/i'
        """
        flags = ""
        if "(?i)" in pattern:
            pattern = pattern.replace("(?i)", "")
            flags = "i"
        pattern = re.sub(r'^\.\*', '', pattern)
        pattern = re.sub(r'\.\*$', '', pattern)
        pattern = pattern.replace("/", "\\/")
        return f"/{pattern}/{flags}"

    def _tactic_to_classtype(self, tactic: str) -> str:
        """Map a MITRE ATT&CK tactic ID to a Suricata classtype."""
        return self.TACTIC_CLASSTYPE.get(tactic, 'policy-violation')
