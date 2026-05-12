"""Example usage of STIX2Suricata"""

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
print("\nExample 2: STIX Bundle")
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

print("\nDone!")
