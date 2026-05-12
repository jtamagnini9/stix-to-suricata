"""Base handler class"""

from abc import ABC, abstractmethod
from typing import List, Dict
from stix2suricata.core.rule import SuricataRule


class BaseHandler(ABC):
    """Base class for indicator handlers"""

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
