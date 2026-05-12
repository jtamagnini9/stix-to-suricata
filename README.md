# STIX2Suricata

Convert STIX 2.x patterns and indicators to Suricata/Snort rules.

Developed for Resilmesh project.

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

