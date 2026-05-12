#!/usr/bin/env python3
"""
Project Generator for STIX2Suricata
Run this script to create the complete project structure
"""

import os
from pathlib import Path


def create_project_structure():
    """Create the complete project directory structure and files"""
    
    # Define project structure
    structure = {
        'config': [],
        'src/stix2suricata': [],
        'src/stix2suricata/core': [],
        'src/stix2suricata/handlers': [],
        'src/stix2suricata/utils': [],
        'tests': [],
        'examples': [],
    }
    
    # Create directories
    for directory in structure.keys():
        Path(directory).mkdir(parents=True, exist_ok=True)
        print(f"✓ Created directory: {directory}")
    
    # File contents
    files = {
        'setup.py': '''from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

with open("requirements.txt", "r", encoding="utf-8") as fh:
    requirements = [line.strip() for line in fh if line.strip() and not line.startswith("#")]

setup(
    name="stix2suricata",
    version="0.1.0",
    author="InfoCert - Resilmesh Team",
    description="Convert STIX 2.x patterns to Suricata/Snort rules",
    long_description=long_description,
    long_description_content_type="text/markdown",
    package_dir={"": "src"},
    packages=find_packages(where="src"),
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Information Technology",
        "Topic :: Security",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3.8",
    ],
    python_requires=">=3.8",
    install_requires=requirements,
    entry_points={
        "console_scripts": [
            "stix2suricata=stix2suricata.cli:main",
        ],
    },
)
''',
        
        'requirements.txt': '''pyyaml>=6.0
stix2-patterns>=2.0.0
colorama>=0.4.6
''',
        
        'README.md': '''# STIX2Suricata

Convert STIX 2.x patterns and indicators to Suricata/Snort rules.

Developed for Resilmesh project.

## Features

- ✅ Modular architecture for easy extension
- ✅ Support for common network-based STIX indicators
- ✅ Pluggable handler system for new indicator types
- ✅ CLI and Python API
- ✅ YAML configuration
- ✅ Comprehensive logging

## Installation

```bash
pip install -e .
```

## Quick Start

```bash
# Convert STIX pattern to Suricata rule
stix2suricata --pattern "[ipv4-addr:value = '192.168.1.100']"

# Convert STIX bundle file
stix2suricata --input threat_feed.json --output rules.rules

# With custom SID range
stix2suricata --input bundle.json --sid-start 5000000
```

## Python API

```python
from stix2suricata import StixConverter

converter = StixConverter(starting_sid=5000000)
converter.register_default_handlers()
rules = converter.convert_pattern("[domain-name:value = 'evil.com']")
converter.save_rules(rules, "output.rules")
```

## Extending with Custom Handlers

Create a new handler by inheriting from `BaseHandler`:

```python
from stix2suricata.handlers.base import BaseHandler
from stix2suricata.core.rule import SuricataRule

class CustomHandler(BaseHandler):
    def can_handle(self, indicator_type: str) -> bool:
        return indicator_type == "custom-type"
    
    def handle(self, indicator: dict, config=None) -> list:
        rule = SuricataRule(
            protocol="tcp",
            options=[f'msg:"Custom indicator"']
        )
        return [rule]

# Register the handler
converter.register_handler(CustomHandler())
```

## Configuration

Edit `config/config.yaml` to customize:
- Default SID ranges
- Rule priorities
- Classification types
- Output formats

## Project Structure

```
stix2suricata/
├── src/stix2suricata/
│   ├── core/          # Core conversion logic
│   ├── handlers/      # Indicator type handlers
│   └── utils/         # Utilities and configuration
├── tests/             # Unit tests
├── examples/          # Usage examples
└── config/            # Configuration files
```

## License

MIT License
''',
        
        'config/config.yaml': '''# STIX2Suricata Configuration

suricata:
  sid_start: 5000000
  default_priority: 2
  default_classtype: "trojan-activity"
  default_action: "alert"

handlers:
  enabled:
    - network
    - domain
    - url
    - ipv4
    - ipv6

logging:
  level: INFO
  format: "%(asctime)s - %(name)s - %(levelname)s - %(message)s"

output:
  include_metadata: true
  include_comments: true
''',
        
        'src/stix2suricata/__init__.py': '''"""STIX2Suricata - Convert STIX patterns to Suricata rules"""

__version__ = "0.1.0"

from stix2suricata.core.converter import StixConverter
from stix2suricata.core.rule import SuricataRule
from stix2suricata.handlers.base import BaseHandler

__all__ = ["StixConverter", "SuricataRule", "BaseHandler"]
''',
        
        'src/stix2suricata/core/__init__.py': '''"""Core conversion functionality"""
''',
        
        'src/stix2suricata/core/rule.py': '''"""Suricata rule representation and generation"""

from dataclasses import dataclass, field
from typing import List


@dataclass
class SuricataRule:
    """Represents a Suricata/Snort rule"""
    action: str = "alert"
    protocol: str = "ip"
    src_ip: str = "any"
    src_port: str = "any"
    direction: str = "->"
    dst_ip: str = "any"
    dst_port: str = "any"
    options: List[str] = field(default_factory=list)
    metadata: dict = field(default_factory=dict)
    
    def add_option(self, option: str):
        """Add an option to the rule"""
        self.options.append(option)
    
    def to_rule(self, sid: int) -> str:
        """Convert to Suricata rule string"""
        opts = "; ".join(self.options)
        if opts:
            opts = f"({opts}; sid:{sid};)"
        else:
            opts = f"(sid:{sid};)"
        
        return f"{self.action} {self.protocol} {self.src_ip} {self.src_port} {self.direction} {self.dst_ip} {self.dst_port} {opts}"
    
    def to_rule_with_comment(self, sid: int, comment: str = None) -> str:
        """Convert to rule with optional comment"""
        rule = self.to_rule(sid)
        if comment:
            return f"# {comment}\\n{rule}"
        return rule
''',
        
        'src/stix2suricata/core/parser.py': '''"""STIX pattern parser"""

import re
from typing import List, Dict


class StixPatternParser:
    """Parse STIX patterns and extract indicators"""
    
    # Regex patterns for common STIX objects
    PATTERNS = {
        'ipv4': r"ipv4-addr:value\\s*=\\s*'([^']+)'",
        'ipv6': r"ipv6-addr:value\\s*=\\s*'([^']+)'",
        'domain': r"domain-name:value\\s*=\\s*'([^']+)'",
        'url': r"url:value\\s*=\\s*'([^']+)'",
        'network_src': r"network-traffic:src_ref\\.value\\s*=\\s*'([^']+)'",
        'network_dst': r"network-traffic:dst_ref\\.value\\s*=\\s*'([^']+)'",
        'network_src_port': r"network-traffic:src_port\\s*=\\s*(\\d+)",
        'network_dst_port': r"network-traffic:dst_port\\s*=\\s*(\\d+)",
        'network_protocol': r"network-traffic:protocols\\[0\\]\\s*=\\s*'([^']+)'",
        'file_hash_md5': r"file:hashes\\.MD5\\s*=\\s*'([^']+)'",
        'file_hash_sha256': r"file:hashes\\.'SHA-256'\\s*=\\s*'([^']+)'",
        'email_from': r"email-message:from_ref\\.value\\s*=\\s*'([^']+)'",
        'email_subject': r"email-message:subject\\s*=\\s*'([^']+)'",
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
''',
        
        'src/stix2suricata/core/converter.py': '''"""Main converter class"""

import logging
from typing import List, Dict, Optional
from stix2suricata.core.parser import StixPatternParser
from stix2suricata.core.rule import SuricataRule
from stix2suricata.handlers.base import BaseHandler
from stix2suricata.utils.config import Config


class StixConverter:
    """Main converter class - orchestrates parsing and rule generation"""
    
    def __init__(self, config: Optional[Config] = None, starting_sid: int = None):
        self.config = config or Config()
        self.parser = StixPatternParser()
        self.handlers: List[BaseHandler] = []
        self.logger = logging.getLogger(__name__)
        
        # SID management
        self.sid_counter = starting_sid or self.config.get('suricata.sid_start', 5000000)
        
    def register_handler(self, handler: BaseHandler):
        """Register a new indicator handler"""
        self.handlers.append(handler)
        self.logger.debug(f"Registered handler: {handler.__class__.__name__}")
    
    def register_default_handlers(self):
        """Register all default handlers"""
        from stix2suricata.handlers.network import NetworkHandler
        from stix2suricata.handlers.domain import DomainHandler
        from stix2suricata.handlers.url import URLHandler
        
        self.register_handler(NetworkHandler(self.config))
        self.register_handler(DomainHandler(self.config))
        self.register_handler(URLHandler(self.config))
    
    def get_next_sid(self) -> int:
        """Get next available SID"""
        sid = self.sid_counter
        self.sid_counter += 1
        return sid
    
    def convert_indicator(self, indicator: Dict) -> List[str]:
        """Convert a single indicator to Suricata rules"""
        rules = []
        
        for handler in self.handlers:
            if handler.can_handle(indicator['type']):
                self.logger.debug(f"Handler {handler.__class__.__name__} processing {indicator['type']}")
                handler_rules = handler.handle(indicator, self.config)
                
                # Convert to rule strings with SIDs
                for rule in handler_rules:
                    sid = self.get_next_sid()
                    rule_str = rule.to_rule(sid)
                    rules.append(rule_str)
                
                break  # First handler wins
        else:
            self.logger.warning(f"No handler found for indicator type: {indicator['type']}")
        
        return rules
    
    def convert_pattern(self, pattern: str, metadata: Optional[Dict] = None) -> List[str]:
        """Convert STIX pattern to Suricata rules"""
        indicators = self.parser.parse(pattern)
        rules = []
        
        for indicator in indicators:
            if metadata:
                indicator['stix_metadata'] = metadata
            rule_strings = self.convert_indicator(indicator)
            rules.extend(rule_strings)
        
        return rules
    
    def convert_bundle(self, bundle: Dict) -> List[str]:
        """Convert STIX bundle to Suricata rules"""
        indicators = self.parser.parse_bundle(bundle)
        rules = []
        
        for indicator in indicators:
            rule_strings = self.convert_indicator(indicator)
            rules.extend(rule_strings)
        
        return rules
    
    def save_rules(self, rules: List[str], filename: str, include_header: bool = True):
        """Save rules to file"""
        with open(filename, 'w') as f:
            if include_header:
                f.write("# Generated by STIX2Suricata\\n")
                f.write(f"# Total rules: {len(rules)}\\n")
                f.write("# \\n")
            
            for rule in rules:
                f.write(rule + '\\n')
        
        self.logger.info(f"Saved {len(rules)} rules to {filename}")
''',
        
        'src/stix2suricata/handlers/__init__.py': '''"""Indicator handlers"""
''',
        
        'src/stix2suricata/handlers/base.py': '''"""Base handler class"""

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
        priority = self.config.get('suricata.default_priority', 2) if self.config else 2
        classtype = self.config.get('suricata.default_classtype', 'trojan-activity') if self.config else 'trojan-activity'
        
        return [
            f'msg:"{message}"',
            f'classtype:{classtype}',
            f'priority:{priority}'
        ]
''',
        
        'src/stix2suricata/handlers/network.py': '''"""Network traffic handler"""

from typing import List, Dict
from stix2suricata.handlers.base import BaseHandler
from stix2suricata.core.rule import SuricataRule


class NetworkHandler(BaseHandler):
    """Handler for network-based indicators (IPv4, IPv6, network traffic)"""
    
    def can_handle(self, indicator_type: str) -> bool:
        return indicator_type in ['ipv4', 'ipv6', 'network_src', 'network_dst', 
                                   'network_src_port', 'network_dst_port']
    
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
        
        elif indicator_type == 'network_src':
            rule = SuricataRule(
                protocol="tcp",
                src_ip=value,
                options=self.get_default_options(f"STIX IOC - {threat_type} - Source IP {value}")
            )
            return [rule]
        
        elif indicator_type == 'network_dst':
            rule = SuricataRule(
                protocol="tcp",
                dst_ip=value,
                options=self.get_default_options(f"STIX IOC - {threat_type} - Destination IP {value}")
            )
            return [rule]
        
        return []
''',
        
        'src/stix2suricata/handlers/domain.py': '''"""Domain name handler"""

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
        
        options = self.get_default_options(f"STIX IOC - {threat_type} - Domain {value}")
        options.insert(1, f'dns.query; content:"{value}"; nocase')
        
        rule = SuricataRule(
            protocol="dns",
            options=options
        )
        
        return [rule]
''',
        
        'src/stix2suricata/handlers/url.py': '''"""URL handler"""

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
        
        # Extract path from URL if possible
        path = value
        if '://' in value:
            path = value.split('://', 1)[1]
            if '/' in path:
                path = '/' + path.split('/', 1)[1]
        
        options = self.get_default_options(f"STIX IOC - {threat_type} - URL")
        options.insert(1, f'http.uri; content:"{path}"; nocase')
        
        rule = SuricataRule(
            protocol="http",
            options=options
        )
        
        return [rule]
''',
        
        'src/stix2suricata/utils/__init__.py': '''"""Utility modules"""
''',
        
        'src/stix2suricata/utils/config.py': '''"""Configuration management"""

import yaml
import os
from typing import Any


class Config:
    """Configuration handler"""
    
    def __init__(self, config_path: str = None):
        self.config = {}
        
        if config_path and os.path.exists(config_path):
            self.load(config_path)
        else:
            self.load_defaults()
    
    def load(self, config_path: str):
        """Load configuration from YAML file"""
        with open(config_path, 'r') as f:
            self.config = yaml.safe_load(f)
    
    def load_defaults(self):
        """Load default configuration"""
        self.config = {
            'suricata': {
                'sid_start': 5000000,
                'default_priority': 2,
                'default_classtype': 'trojan-activity',
                'default_action': 'alert'
            },
            'logging': {
                'level': 'INFO'
            }
        }
    
    def get(self, key: str, default: Any = None) -> Any:
        """Get configuration value using dot notation"""
        keys = key.split('.')
        value = self.config
        
        for k in keys:
            if isinstance(value, dict) and k in value:
                value = value[k]
            else:
                return default
        
        return value
''',
        
        'src/stix2suricata/utils/logger.py': '''"""Logging configuration"""

import logging
import sys
from colorama import Fore, Style, init

# Initialize colorama
init(autoreset=True)


class ColoredFormatter(logging.Formatter):
    """Custom formatter with colors"""
    
    COLORS = {
        'DEBUG': Fore.CYAN,
        'INFO': Fore.GREEN,
        'WARNING': Fore.YELLOW,
        'ERROR': Fore.RED,
        'CRITICAL': Fore.RED + Style.BRIGHT
    }
    
    def format(self, record):
        levelname = record.levelname
        if levelname in self.COLORS:
            record.levelname = f"{self.COLORS[levelname]}{levelname}{Style.RESET_ALL}"
        return super().format(record)


def setup_logging(level: str = 'INFO'):
    """Setup logging configuration"""
    handler = logging.StreamHandler(sys.stdout)
    formatter = ColoredFormatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    handler.setFormatter(formatter)
    
    root_logger = logging.getLogger()
    root_logger.setLevel(getattr(logging, level.upper()))
    root_logger.addHandler(handler)
''',
        
        'src/stix2suricata/cli.py': '''"""Command-line interface"""

import argparse
import json
import sys
import logging
from pathlib import Path

from stix2suricata import StixConverter
from stix2suricata.utils.config import Config
from stix2suricata.utils.logger import setup_logging


def main():
    """Main CLI entry point"""
    parser = argparse.ArgumentParser(
        description='Convert STIX 2.x patterns to Suricata/Snort rules',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    parser.add_argument(
        '-i', '--input',
        help='Input STIX bundle JSON file'
    )
    
    parser.add_argument(
        '-o', '--output',
        help='Output Suricata rules file'
    )
    
    parser.add_argument(
        '-p', '--pattern',
        help='Single STIX pattern to convert'
    )
    
    parser.add_argument(
        '--sid-start',
        type=int,
        default=5000000,
        help='Starting SID number (default: 5000000)'
    )
    
    parser.add_argument(
        '-c', '--config',
        help='Configuration file path'
    )
    
    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Verbose output'
    )
    
    args = parser.parse_args()
    
    # Setup logging
    log_level = 'DEBUG' if args.verbose else 'INFO'
    setup_logging(log_level)
    logger = logging.getLogger(__name__)
    
    # Load configuration
    config = Config(args.config) if args.config else Config()
    
    # Initialize converter
    converter = StixConverter(config=config, starting_sid=args.sid_start)
    converter.register_default_handlers()
    
    rules = []
    
    try:
        # Process input
        if args.pattern:
            logger.info(f"Converting pattern: {args.pattern}")
            rules = converter.convert_pattern(args.pattern)
        
        elif args.input:
            logger.info(f"Reading STIX bundle from: {args.input}")
            with open(args.input, 'r') as f:
                bundle = json.load(f)
            rules = converter.convert_bundle(bundle)
        
        else:
            parser.print_help()
            sys.exit(1)
        
        # Output results
        if not rules:
            logger.warning("No rules generated")
            sys.exit(0)
        
        if args.output:
            converter.save_rules(rules, args.output)
            logger.info(f"Saved {len(rules)} rules to {args.output}")
        else:
            print("\\n# Generated Suricata Rules\\n")
            for rule in rules:
                print(rule)
        
        logger.info(f"Successfully generated {len(rules)} rules")
    
    except Exception as e:
        logger.error(f"Error: {e}", exc_info=args.verbose)
        sys.exit(1)


if __name__ == '__main__':
    main()
''',
        
        'tests/__init__.py': '"""Test suite"""',
        
        'tests/test_converter.py': '''"""Tests for converter"""

import unittest
from stix2suricata import StixConverter
from stix2suricata.utils.config import Config


class TestConverter(unittest.TestCase):
    """Test converter functionality"""
    
    def setUp(self):
        self.config = Config()
        self.converter = StixConverter(config=self.config, starting_sid=9000000)
        self.converter.register_default_handlers()
    
    def test_ipv4_conversion(self):
        """Test IPv4 indicator conversion"""
        pattern = "[ipv4-addr:value = '192.168.1.100']"
        rules = self.converter.convert_pattern(pattern)
        
        self.assertEqual(len(rules), 1)
        self.assertIn('192.168.1.100', rules[0])
        self.assertIn('sid:9000000', rules[0])
    
    def test_domain_conversion(self):
        """Test domain indicator conversion"""
        pattern = "[domain-name:value = 'evil.example.com']"
        rules = self.converter.convert_pattern(pattern)
        
        self.assertEqual(len(rules), 1)
        self.assertIn('evil.example.com', rules[0])
        self.assertIn('dns', rules[0])
    
    def test_url_conversion(self):
        """Test URL indicator conversion"""
        pattern = "[url:value = 'http://malicious.com/payload.exe']"
        rules = self.converter.convert_pattern(pattern)
        
        self.assertEqual(len(rules), 1)
        self.assertIn('http', rules[0])


if __name__ == '__main__':
    unittest.main()
''',
        
        'examples/usage.py': '''"""Example usage of STIX2Suricata"""

from stix2suricata import StixConverter
from stix2suricata.utils.config import Config

# Initialize converter
config = Config()
converter = StixConverter(config=config, starting_sid=5000000)
converter.register_default_handlers()

# Example 1: Convert single pattern
print("Example 1: Single Pattern")
print("-" * 60)
pattern = "[ipv4-addr:value = '192.168.1.100']"
rules = converter.convert_pattern(pattern)
for rule in rules:
    print(rule)

# Example 2: Convert STIX bundle
print("\\nExample 2: STIX Bundle")
print("-" * 60)
bundle = {
    "type": "bundle",
    "objects": [
        {
            "type": "indicator",
            "pattern": "[domain-name:value = 'phishing.example.com']",
            "labels": ["phishing"],
            "name": "Phishing Domain",
            "description": "Known phishing infrastructure"
        }
    ]
}

rules = converter.convert_bundle(bundle)
for rule in rules:
    print(rule)

print("\\nDone!")
''',
        
        'examples/sample_stix.json': '''{
  "type": "bundle",
  "id": "bundle--example-001",
  "objects": [
    {
      "type": "indicator",
      "id": "indicator--c1c3e8c2-7d72-4f8e-a7e4-25f9f6e7a7a7",
      "pattern": "[ipv4-addr:value = '203.0.113.42']",
      "labels": ["malicious-activity"],
      "name": "C2 Server IP",
      "description": "Known command and control server",
      "created": "2025-10-01T10:00:00.000Z",
      "modified": "2025-10-01T10:00:00.000Z"
    },
    {
      "type": "indicator",
      "id": "indicator--d2e4f9d3-8e83-5g9f-b8f5-36g0g7f8b8b8",
      "pattern": "[domain-name:value = 'evil.example.com']",
      "labels": ["phishing"],
      "name": "Phishing Domain",
      "description": "Active phishing campaign",
      "created": "2025-10-02T14:30:00.000Z",
      "modified": "2025-10-02T14:30:00.000Z"
    }
  ]
}
''',
        
        '.gitignore': '''# Python
__pycache__/
*.py[cod]
*$py.class
*.so
.Python
build/
develop-eggs/
dist/
downloads/
eggs/
.eggs/
lib/
lib64/
parts/
sdist/
var/
wheels/
*.egg-info/
.installed.cfg
*.egg

# Virtual environments
venv/
ENV/
env/

# IDE
.vscode/
.idea/
*.swp
*.swo

# Output
*.rules
output*.rules
''',
    }
    
    # Create all files
    for filepath, content in files.items():
        with open(filepath, 'w') as f:
            f.write(content)
        print(f"✓ Created file: {filepath}")
    
    print("\n" + "="*60)
    print("✅ Project structure created successfully!")
    print("="*60)
    print("\nNext steps:")
    print("1. cd into the project directory")
    print("2. Create virtual environment: python3 -m venv venv")
    print("3. Activate it: source venv/bin/activate")
    print("4. Install: pip install -e .")
    print("5. Test: stix2suricata --pattern \"[ipv4-addr:value = '10.0.0.1']\"")
    print("\nTo run tests: python -m unittest discover tests")
    print("To see examples: python examples/usage.py")


if __name__ == "__main__":
    create_project_structure()
