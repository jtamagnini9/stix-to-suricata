# STIX2Suricata

Convert STIX 2.x patterns and OCA IoB bundles to Suricata rules.

Developed for the [Resilmesh](https://resilmesh.eu) project.

## Features

- Convert standard STIX 2.1 `indicator` objects to Suricata rules
- Auto-detect and parse **OCA IoB bundles** (`x-oca-detection` / `x-oca-behavior`) with base64-encoded STIX patterns
- Support for both exact-match (`=`) and regex (`MATCHES`) operators
- Enrich generated rules with **MITRE ATT&CK metadata** (technique, tactic, STIX ID)
- **Directory watcher** — monitor a folder for incoming `peer-*.json` bundles and forward rules to an HTTP endpoint, with deduplication and retry across restarts

## Installation

```bash
pip install -e .
```

## Quick Start

### Convert a single pattern

```bash
stix2suricata -p "[ipv4-addr:value = '192.168.1.100']"
```

### Convert a STIX bundle file

```bash
stix2suricata -i threat_feed.json -o rules.rules
```

### Watch a directory for incoming OCA IoB bundles

```bash
stix2suricata watch \
  --dir /var/stix/incoming \
  --endpoint http://192.168.1.10/suricataRule \
  --interval 5
```

## CLI Reference

### Convert mode (default)

```
stix2suricata [-i INPUT] [-o OUTPUT] [-p PATTERN] [--sid-start N] [-c CONFIG] [-v]
```

| Flag | Description |
|------|-------------|
| `-i`, `--input` | Input STIX bundle JSON file |
| `-o`, `--output` | Output Suricata rules file (prints to stdout if omitted) |
| `-p`, `--pattern` | Single STIX pattern to convert |
| `--sid-start` | Starting SID number (default: `5000000`) |
| `-c`, `--config` | Path to a custom `config.yaml` |
| `-v`, `--verbose` | Enable debug logging |

### Watch mode

```
stix2suricata watch --dir DIR --endpoint URL [options]
```

| Flag | Description |
|------|-------------|
| `--dir` | Directory to monitor for `peer-*.json` files **(required)** |
| `--endpoint` | HTTP endpoint URL, e.g. `http://ip/suricataRule` **(required)** |
| `--interval` | Polling interval in seconds (default: `5`) |
| `--state-file` | State file path (default: `<dir>/.watcher_state.json`) |
| `--retries` | Max HTTP retries per rule (default: `3`) |
| `--sid-start` | Starting SID for rule generation (default: `5000000`) |
| `-v`, `--verbose` | Enable debug logging |

## OCA IoB Bundle Support

The converter auto-detects OCA bundles. No flag needed — just pass the file:

```bash
stix2suricata -i peer-bundle.json
```

OCA bundles contain `x-oca-detection` objects with a base64-encoded STIX pattern in `analytic.rule` and linked `x-oca-behavior` objects carrying MITRE ATT&CK metadata. The converter:

1. Decodes the base64 pattern
2. Follows the `detects` relationship to retrieve the linked behavior
3. Extracts `technique` and `tactic` from the behavior
4. Generates a Suricata rule enriched with a `metadata` keyword

Example output for an LFI detection:

```
alert http any any -> any any (
  msg:"Wazuh Detection for LFI - /etc/passwd access";
  flow:established,to_server;
  http.uri; pcre:"/etc\/passwd/";
  classtype:web-application-attack;
  metadata:mitre_technique T1190, mitre_tactic TA0001,
           stix_id x-oca-detection--74a81dee-...;
  sid:5000000; rev:1;
)
```

### Supported STIX pattern types

| STIX pattern | Operator | Suricata rule |
|---|---|---|
| `ipv4-addr:value` | `=` | `alert ip <src> any → any any` |
| `domain-name:value` | `=` | `dns.query; content:"..."` |
| `domain-name:value` | `MATCHES` | `dns.query; pcre:"..."` |
| `url:value` | `=` | `http.host; content:"..."; http.uri; content:"..."` |
| `url:value` | `MATCHES` | `http.uri; pcre:"..."` |
| `process:command_line` | `MATCHES` | ⚠ skipped (host-based, not network-detectable) |

### MITRE tactic → Suricata classtype mapping

| Tactic | Classtype |
|---|---|
| TA0001 — Initial Access | `web-application-attack` |
| TA0002 — Execution | `attempted-admin` |
| TA0007 — Discovery | `network-scan` |
| TA0040 — Impact | `denial-of-service` |
| *(other)* | `policy-violation` |

## Directory Watcher

The watcher polls a directory every N seconds for files matching `peer-*.json`, converts each bundle to Suricata rules, and POSTs each rule individually to the configured endpoint.

```
POST http://ip/suricataRule
Content-Type: application/json

{"rule": "alert http any any -> any any (...)", "source_file": "peer-001.json"}
```

### Deduplication

Rule identity is determined by SHA-256 of the rule string with `sid:N;` stripped. A rule already delivered to the endpoint is **never re-sent**, even if the SID counter resets after a restart.

### State file

The watcher persists its state in `<dir>/.watcher_state.json` (configurable via `--state-file`):

```json
{
  "processed": ["peer-001.json", "peer-002.json"],
  "sent_hashes": ["a3f2c1...", "b8e4d2..."]
}
```

- **`processed`** — bundles whose rules were all sent successfully; skipped on next scan
- **`sent_hashes`** — hashes of individual rules already delivered; prevents re-sending on partial retry

### Retry behavior

| HTTP response | Action |
|---|---|
| 2xx | Rule marked as sent ✅ |
| 4xx | Warning logged, rule skipped (no retry) |
| 5xx / timeout | Retry up to `--retries` times with 2s / 4s backoff |

If any rule in a bundle fails to send, the bundle is **not** added to `processed` and will be retried on the next scan cycle. Already-sent rules within that bundle are skipped on retry.

## Python API

```python
from stix2suricata import StixConverter
from stix2suricata.utils.config import Config

converter = StixConverter(config=Config(), starting_sid=5000000)
converter.register_default_handlers()

# Convert a single pattern
rules = converter.convert_pattern("[domain-name:value = 'evil.com']")

# Convert a standard STIX bundle (auto-detects OCA bundles too)
import json
with open('bundle.json') as f:
    bundle = json.load(f)
rules = converter.convert_bundle(bundle)

converter.save_rules(rules, "output.rules")
```

## Extending with Custom Handlers

Subclass `BaseHandler` to add support for new STIX indicator types:

```python
from stix2suricata.handlers.base import BaseHandler
from stix2suricata.core.rule import SuricataRule

class CustomHandler(BaseHandler):
    def can_handle(self, indicator_type: str) -> bool:
        return indicator_type == "my-custom-type"

    def handle(self, indicator: dict, config=None) -> list:
        rule = SuricataRule(
            protocol="tcp",
            options=[f'msg:"Custom indicator: {indicator["value"]}"']
        )
        return [rule]

converter.register_handler(CustomHandler())
```

`BaseHandler` also provides two shared helpers available in all handlers:

- `_regex_to_pcre(pattern)` — converts a STIX regex string to Suricata `pcre` format (strips `.*` anchors, extracts `(?i)` flag, escapes `/`)
- `_tactic_to_classtype(tactic)` — maps a MITRE tactic ID to a Suricata `classtype` string

## Configuration

Edit `config/config.yaml` to customize defaults:

```yaml
suricata:
  sid_start: 5000000
  default_priority: 2
  default_classtype: "trojan-activity"
  default_action: "alert"
```

## Running Tests

```bash
source venv/bin/activate && python -m pytest tests/ -v
```