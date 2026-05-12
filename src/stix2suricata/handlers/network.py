"""Network traffic handler"""

from typing import List, Dict
from stix2suricata.handlers.base import BaseHandler
from stix2suricata.core.rule import SuricataRule


class NetworkHandler(BaseHandler):
    """Handler for network-based indicators (IPv4, IPv6, network traffic)"""
    
    def can_handle(self, indicator_type: str) -> bool:
        return indicator_type in ['ipv4', 'ipv6']
    
    def handle(self, indicator: Dict, config=None) -> List[SuricataRule]:
        """Convert network indicator to Suricata rule"""
        indicator_type = indicator['type']
        value = indicator['value']
        metadata = indicator.get('stix_metadata', {})
        
        # Determine threat type from metadata
        threat_type = "Suspicious activity"
        if metadata.get('labels'):
            threat_type = metadata['labels'][0]
        
        if indicator_type in ['ipv4', 'ipv6']:
            rule = SuricataRule(
                protocol="ip",
                src_ip=value,
                options=self.get_default_options(f"STIX IOC - {threat_type} - IP {value}")
            )
            return [rule]
        
        return []
