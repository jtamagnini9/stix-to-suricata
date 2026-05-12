"""STIX2Suricata - Convert STIX patterns to Suricata rules"""

__version__ = "0.1.0"

from stix2suricata.core.converter import StixConverter
from stix2suricata.core.rule import SuricataRule
from stix2suricata.handlers.base import BaseHandler

__all__ = ["StixConverter", "SuricataRule", "BaseHandler"]
