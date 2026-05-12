# OCA Bundle Support Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Extend `stix2suricata` to parse Resilmesh OCA bundles (`x-oca-detection` / `x-oca-behavior` objects) and generate Suricata rules with pcre matching and MITRE ATT&CK metadata.

**Architecture:** A new `OCABundleParser` class handles OCA-specific bundle parsing (base64 decode, relationship resolution, MITRE metadata extraction) and produces the same indicator dict format the existing pipeline already consumes. `StixConverter.convert_bundle()` auto-detects the bundle format by checking for `x-oca-detection` objects and routes accordingly. Existing handlers are extended in-place to support the `MATCHES` operator via a new `_regex_to_pcre()` helper on `BaseHandler`.

**Tech Stack:** Python 3.12, pytest, existing `stix2suricata` package. No new dependencies.

---

## File Map

| Action | File | What changes |
|--------|------|-------------|
| Modify | `src/stix2suricata/core/rule.py` | Add `rev:1` to `to_rule()` output |
| Modify | `src/stix2suricata/handlers/base.py` | Add `_regex_to_pcre()` and `_tactic_to_classtype()` |
| Modify | `src/stix2suricata/core/parser.py` | Add `MATCHES` regex patterns for url, domain, process |
| Modify | `src/stix2suricata/handlers/url.py` | Handle `url_matches` type with pcre rule |
| Modify | `src/stix2suricata/handlers/domain.py` | Handle `domain_matches` type with pcre rule |
| Create | `src/stix2suricata/core/oca_parser.py` | `OCABundleParser` class |
| Modify | `src/stix2suricata/core/converter.py` | Auto-detect OCA format in `convert_bundle()` |
| Create | `tests/test_rule.py` | Tests for `rev:1` |
| Create | `tests/test_base_handler.py` | Tests for `_regex_to_pcre()` and `_tactic_to_classtype()` |
| Create | `tests/test_parser_matches.py` | Tests for MATCHES pattern extraction |
| Create | `tests/test_url_handler_matches.py` | Tests for `URLHandler` with `url_matches` |
| Create | `tests/test_domain_handler_matches.py` | Tests for `DomainHandler` with `domain_matches` |
| Create | `tests/test_oca_parser.py` | Tests for `OCABundleParser` |
| Create | `tests/test_converter_oca.py` | Integration test: OCA bundle → rule strings |

---

## Task 1: Add `rev:1` to `SuricataRule.to_rule()`

**Files:**
- Modify: `src/stix2suricata/core/rule.py`
- Test: `tests/test_rule.py`

- [ ] **Step 1: Write the failing test**

Create `tests/test_rule.py`:

```python
import unittest
from stix2suricata.core.rule import SuricataRule


class TestSuricataRule(unittest.TestCase):

    def test_to_rule_contains_rev1(self):
        rule = SuricataRule(options=['msg:"test"'])
        result = rule.to_rule(1000)
        self.assertIn('rev:1', result)

    def test_to_rule_empty_options_contains_rev1(self):
        rule = SuricataRule()
        result = rule.to_rule(1001)
        self.assertIn('rev:1', result)
        self.assertIn('sid:1001', result)

    def test_to_rule_rev1_after_sid(self):
        rule = SuricataRule(options=['msg:"test"'])
        result = rule.to_rule(1002)
        sid_pos = result.index('sid:1002')
        rev_pos = result.index('rev:1')
        self.assertGreater(rev_pos, sid_pos)


if __name__ == '__main__':
    unittest.main()
```

- [ ] **Step 2: Run test to confirm it fails**

```bash
source venv/bin/activate && python -m pytest tests/test_rule.py -v
```

Expected: FAIL — `AssertionError: 'rev:1' not found in ...`

- [ ] **Step 3: Implement the change in `rule.py`**

In `src/stix2suricata/core/rule.py`, replace the `to_rule` method body:

```python
def to_rule(self, sid: int) -> str:
    """Convert to Suricata rule string"""
    opts = "; ".join(self.options)
    if opts:
        opts = f"({opts}; sid:{sid}; rev:1;)"
    else:
        opts = f"(sid:{sid}; rev:1;)"

    return f"{self.action} {self.protocol} {self.src_ip} {self.src_port} {self.direction} {self.dst_ip} {self.dst_port} {opts}"
```

- [ ] **Step 4: Run tests to confirm they pass**

```bash
source venv/bin/activate && python -m pytest tests/test_rule.py tests/test_converter.py -v
```

Expected: 6 passed (3 new + 3 existing)

- [ ] **Step 5: Commit**

```bash
git add src/stix2suricata/core/rule.py tests/test_rule.py
git commit -m "feat: add rev:1 to generated Suricata rules"
```

---

## Task 2: Add `_regex_to_pcre()` and `_tactic_to_classtype()` to `BaseHandler`

**Files:**
- Modify: `src/stix2suricata/handlers/base.py`
- Test: `tests/test_base_handler.py`

- [ ] **Step 1: Write the failing tests**

Create `tests/test_base_handler.py`:

```python
import unittest
from stix2suricata.handlers.url import URLHandler


class TestBaseHandlerHelpers(unittest.TestCase):
    """Test helper methods inherited from BaseHandler via URLHandler."""

    def setUp(self):
        self.handler = URLHandler(config=None)

    # _regex_to_pcre tests

    def test_pcre_strips_leading_dot_star(self):
        self.assertEqual(self.handler._regex_to_pcre('.*etc/passwd.*'), '/etc\\/passwd/')

    def test_pcre_preserves_pattern_without_anchors(self):
        self.assertEqual(self.handler._regex_to_pcre('nmap'), '/nmap/')

    def test_pcre_extracts_case_insensitive_flag(self):
        self.assertEqual(self.handler._regex_to_pcre('(?i)nmap'), '/nmap/i')

    def test_pcre_flag_and_anchors_combined(self):
        self.assertEqual(self.handler._regex_to_pcre('(?i).*nmap.*'), '/nmap/i')

    def test_pcre_escapes_forward_slash(self):
        self.assertEqual(self.handler._regex_to_pcre('etc/passwd'), '/etc\\/passwd/')

    def test_pcre_only_leading_anchor(self):
        self.assertEqual(self.handler._regex_to_pcre('.*nmap'), '/nmap/')

    def test_pcre_only_trailing_anchor(self):
        self.assertEqual(self.handler._regex_to_pcre('nmap.*'), '/nmap/')

    # _tactic_to_classtype tests

    def test_ta0001_maps_to_web_application_attack(self):
        self.assertEqual(self.handler._tactic_to_classtype('TA0001'), 'web-application-attack')

    def test_ta0007_maps_to_network_scan(self):
        self.assertEqual(self.handler._tactic_to_classtype('TA0007'), 'network-scan')

    def test_ta0002_maps_to_attempted_admin(self):
        self.assertEqual(self.handler._tactic_to_classtype('TA0002'), 'attempted-admin')

    def test_ta0040_maps_to_denial_of_service(self):
        self.assertEqual(self.handler._tactic_to_classtype('TA0040'), 'denial-of-service')

    def test_unknown_tactic_falls_back_to_policy_violation(self):
        self.assertEqual(self.handler._tactic_to_classtype('TA9999'), 'policy-violation')

    def test_empty_tactic_falls_back_to_policy_violation(self):
        self.assertEqual(self.handler._tactic_to_classtype(''), 'policy-violation')


if __name__ == '__main__':
    unittest.main()
```

- [ ] **Step 2: Run tests to confirm they fail**

```bash
source venv/bin/activate && python -m pytest tests/test_base_handler.py -v
```

Expected: FAIL — `AttributeError: 'URLHandler' object has no attribute '_regex_to_pcre'`

- [ ] **Step 3: Implement helpers in `base.py`**

Replace the full content of `src/stix2suricata/handlers/base.py`:

```python
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
```

- [ ] **Step 4: Run tests to confirm they pass**

```bash
source venv/bin/activate && python -m pytest tests/test_base_handler.py tests/test_rule.py tests/test_converter.py -v
```

Expected: all pass

- [ ] **Step 5: Commit**

```bash
git add src/stix2suricata/handlers/base.py tests/test_base_handler.py
git commit -m "feat: add _regex_to_pcre and _tactic_to_classtype helpers to BaseHandler"
```

---

## Task 3: Add `MATCHES` operator support to `StixPatternParser`

**Files:**
- Modify: `src/stix2suricata/core/parser.py`
- Test: `tests/test_parser_matches.py`

- [ ] **Step 1: Write the failing tests**

Create `tests/test_parser_matches.py`:

```python
import unittest
from stix2suricata.core.parser import StixPatternParser


class TestStixPatternParserMatches(unittest.TestCase):

    def setUp(self):
        self.parser = StixPatternParser()

    def test_url_matches_type(self):
        indicators = self.parser.parse("[url:value MATCHES '.*etc/passwd.*']")
        self.assertEqual(len(indicators), 1)
        self.assertEqual(indicators[0]['type'], 'url_matches')

    def test_url_matches_value(self):
        indicators = self.parser.parse("[url:value MATCHES '.*etc/passwd.*']")
        self.assertEqual(indicators[0]['value'], '.*etc/passwd.*')

    def test_domain_matches_type(self):
        indicators = self.parser.parse("[domain-name:value MATCHES '(?i)evil\\.example\\..*']")
        self.assertEqual(len(indicators), 1)
        self.assertEqual(indicators[0]['type'], 'domain_matches')

    def test_domain_matches_value(self):
        indicators = self.parser.parse("[domain-name:value MATCHES '(?i)evil\\.example\\..*']")
        self.assertEqual(indicators[0]['value'], '(?i)evil\\.example\\..*')

    def test_process_command_line_type(self):
        indicators = self.parser.parse("[process:command_line MATCHES '(?i)nmap']")
        self.assertEqual(len(indicators), 1)
        self.assertEqual(indicators[0]['type'], 'process_command_line')

    def test_process_command_line_value(self):
        indicators = self.parser.parse("[process:command_line MATCHES '(?i)nmap']")
        self.assertEqual(indicators[0]['value'], '(?i)nmap')

    def test_exact_match_still_works(self):
        indicators = self.parser.parse("[url:value = 'http://malicious.com/payload.exe']")
        self.assertEqual(indicators[0]['type'], 'url')

    def test_pattern_field_populated(self):
        indicators = self.parser.parse("[url:value MATCHES '.*passwd.*']")
        self.assertIn('pattern', indicators[0])


if __name__ == '__main__':
    unittest.main()
```

- [ ] **Step 2: Run tests to confirm they fail**

```bash
source venv/bin/activate && python -m pytest tests/test_parser_matches.py -v
```

Expected: FAIL — `AssertionError: 0 != 1` (no indicators found for MATCHES patterns)

- [ ] **Step 3: Add MATCHES patterns to `parser.py`**

In `src/stix2suricata/core/parser.py`, add the three new entries to the `PATTERNS` dict:

```python
PATTERNS = {
    'ipv4': r"ipv4-addr:value\s*=\s*'([^']+)'",
    'ipv6': r"ipv6-addr:value\s*=\s*'([^']+)'",
    'domain': r"domain-name:value\s*=\s*'([^']+)'",
    'url': r"url:value\s*=\s*'([^']+)'",
    'network_src': r"network-traffic:src_ref\.value\s*=\s*'([^']+)'",
    'network_dst': r"network-traffic:dst_ref\.value\s*=\s*'([^']+)'",
    'network_src_port': r"network-traffic:src_port\s*=\s*(\d+)",
    'network_dst_port': r"network-traffic:dst_port\s*=\s*(\d+)",
    'network_protocol': r"network-traffic:protocols\[0\]\s*=\s*'([^']+)'",
    'file_hash_md5': r"file:hashes\.MD5\s*=\s*'([^']+)'",
    'file_hash_sha256': r"file:hashes\.'SHA-256'\s*=\s*'([^']+)'",
    'email_from': r"email-message:from_ref\.value\s*=\s*'([^']+)'",
    'email_subject': r"email-message:subject\s*=\s*'([^']+)'",
    'url_matches': r"url:value\s+MATCHES\s+'([^']+)'",
    'domain_matches': r"domain-name:value\s+MATCHES\s+'([^']+)'",
    'process_command_line': r"process:command_line\s+MATCHES\s+'([^']+)'",
}
```

No other changes needed — the existing `parse()` loop handles all entries in `PATTERNS` uniformly.

- [ ] **Step 4: Run tests to confirm they pass**

```bash
source venv/bin/activate && python -m pytest tests/test_parser_matches.py tests/test_converter.py -v
```

Expected: all pass

- [ ] **Step 5: Commit**

```bash
git add src/stix2suricata/core/parser.py tests/test_parser_matches.py
git commit -m "feat: add MATCHES operator support to StixPatternParser"
```

---

## Task 4: Extend `URLHandler` to generate pcre rules for `url_matches`

**Files:**
- Modify: `src/stix2suricata/handlers/url.py`
- Test: `tests/test_url_handler_matches.py`

- [ ] **Step 1: Write the failing tests**

Create `tests/test_url_handler_matches.py`:

```python
import unittest
from stix2suricata.handlers.url import URLHandler


class TestURLHandlerMatches(unittest.TestCase):

    def setUp(self):
        self.handler = URLHandler(config=None)

    def test_can_handle_url_matches(self):
        self.assertTrue(self.handler.can_handle('url_matches'))

    def test_can_handle_url_still_works(self):
        self.assertTrue(self.handler.can_handle('url'))

    def test_cannot_handle_other_types(self):
        self.assertFalse(self.handler.can_handle('ipv4'))

    def test_url_matches_generates_http_rule(self):
        indicator = {
            'type': 'url_matches',
            'value': '.*etc/passwd.*',
            'pattern': "url:value MATCHES '.*etc/passwd.*'",
            'stix_metadata': {
                'id': 'x-oca-detection--74a81dee-43b9-43b8-9b94-949e9b39a6e0',
                'name': 'LFI - /etc/passwd access',
                'technique': 'T1190',
                'tactic': 'TA0001',
            }
        }
        rules = self.handler.handle(indicator)
        self.assertEqual(len(rules), 1)
        rule_str = rules[0].to_rule(5000000)
        self.assertIn('http', rule_str)
        self.assertIn('pcre:', rule_str)
        self.assertIn('etc\\/passwd', rule_str)

    def test_url_matches_classtype_from_tactic(self):
        indicator = {
            'type': 'url_matches',
            'value': '.*etc/passwd.*',
            'pattern': "url:value MATCHES '.*etc/passwd.*'",
            'stix_metadata': {'tactic': 'TA0001', 'name': 'test', 'id': 'x-oca-detection--aaa'}
        }
        rules = self.handler.handle(indicator)
        rule_str = rules[0].to_rule(5000000)
        self.assertIn('web-application-attack', rule_str)

    def test_url_matches_includes_mitre_metadata(self):
        indicator = {
            'type': 'url_matches',
            'value': '.*etc/passwd.*',
            'pattern': "url:value MATCHES '.*etc/passwd.*'",
            'stix_metadata': {
                'id': 'x-oca-detection--74a81dee',
                'name': 'LFI test',
                'technique': 'T1190',
                'tactic': 'TA0001',
            }
        }
        rules = self.handler.handle(indicator)
        rule_str = rules[0].to_rule(5000000)
        self.assertIn('mitre_technique T1190', rule_str)
        self.assertIn('mitre_tactic TA0001', rule_str)
        self.assertIn('stix_id x-oca-detection--74a81dee', rule_str)

    def test_url_matches_no_metadata_still_generates_rule(self):
        indicator = {
            'type': 'url_matches',
            'value': '.*admin.*',
            'pattern': "url:value MATCHES '.*admin.*'",
            'stix_metadata': {}
        }
        rules = self.handler.handle(indicator)
        self.assertEqual(len(rules), 1)
        rule_str = rules[0].to_rule(5000001)
        self.assertIn('pcre:', rule_str)

    def test_url_matches_fallback_classtype_without_tactic(self):
        indicator = {
            'type': 'url_matches',
            'value': '.*test.*',
            'pattern': "url:value MATCHES '.*test.*'",
            'stix_metadata': {'name': 'test', 'id': 'x-oca-detection--bbb'}
        }
        rules = self.handler.handle(indicator)
        rule_str = rules[0].to_rule(5000002)
        self.assertIn('policy-violation', rule_str)


if __name__ == '__main__':
    unittest.main()
```

- [ ] **Step 2: Run tests to confirm they fail**

```bash
source venv/bin/activate && python -m pytest tests/test_url_handler_matches.py -v
```

Expected: FAIL — `can_handle('url_matches')` returns False, others error

- [ ] **Step 3: Update `url.py`**

Replace the full content of `src/stix2suricata/handlers/url.py`:

```python
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
```

- [ ] **Step 4: Run tests to confirm they pass**

```bash
source venv/bin/activate && python -m pytest tests/test_url_handler_matches.py tests/test_converter.py -v
```

Expected: all pass

- [ ] **Step 5: Commit**

```bash
git add src/stix2suricata/handlers/url.py tests/test_url_handler_matches.py
git commit -m "feat: extend URLHandler to generate pcre rules for url_matches indicators"
```

---

## Task 5: Extend `DomainHandler` to generate pcre rules for `domain_matches`

**Files:**
- Modify: `src/stix2suricata/handlers/domain.py`
- Test: `tests/test_domain_handler_matches.py`

- [ ] **Step 1: Write the failing tests**

Create `tests/test_domain_handler_matches.py`:

```python
import unittest
from stix2suricata.handlers.domain import DomainHandler


class TestDomainHandlerMatches(unittest.TestCase):

    def setUp(self):
        self.handler = DomainHandler(config=None)

    def test_can_handle_domain_matches(self):
        self.assertTrue(self.handler.can_handle('domain_matches'))

    def test_can_handle_domain_still_works(self):
        self.assertTrue(self.handler.can_handle('domain'))

    def test_cannot_handle_url(self):
        self.assertFalse(self.handler.can_handle('url'))

    def test_domain_matches_generates_dns_rule(self):
        indicator = {
            'type': 'domain_matches',
            'value': '(?i)evil\\.example\\..*',
            'pattern': "domain-name:value MATCHES '(?i)evil\\.example\\..*'",
            'stix_metadata': {
                'id': 'x-oca-detection--aabbccdd',
                'name': 'Suspicious Domain Pattern',
                'technique': 'T1071',
                'tactic': 'TA0011',
            }
        }
        rules = self.handler.handle(indicator)
        self.assertEqual(len(rules), 1)
        rule_str = rules[0].to_rule(5000010)
        self.assertIn('dns', rule_str)
        self.assertIn('pcre:', rule_str)

    def test_domain_matches_case_insensitive_flag(self):
        indicator = {
            'type': 'domain_matches',
            'value': '(?i)evil.*',
            'pattern': "domain-name:value MATCHES '(?i)evil.*'",
            'stix_metadata': {'name': 'test', 'id': 'x-oca-detection--test', 'tactic': ''}
        }
        rules = self.handler.handle(indicator)
        rule_str = rules[0].to_rule(5000011)
        self.assertIn('/i', rule_str)

    def test_domain_matches_includes_mitre_metadata(self):
        indicator = {
            'type': 'domain_matches',
            'value': '.*evil.*',
            'pattern': "domain-name:value MATCHES '.*evil.*'",
            'stix_metadata': {
                'id': 'x-oca-detection--xyz',
                'name': 'Bad domain',
                'technique': 'T1071',
                'tactic': 'TA0011',
            }
        }
        rules = self.handler.handle(indicator)
        rule_str = rules[0].to_rule(5000012)
        self.assertIn('mitre_technique T1071', rule_str)
        self.assertIn('mitre_tactic TA0011', rule_str)

    def test_domain_matches_fallback_classtype(self):
        indicator = {
            'type': 'domain_matches',
            'value': '.*evil.*',
            'pattern': "domain-name:value MATCHES '.*evil.*'",
            'stix_metadata': {'name': 'test', 'id': 'x-oca-detection--zzz'}
        }
        rules = self.handler.handle(indicator)
        rule_str = rules[0].to_rule(5000013)
        self.assertIn('policy-violation', rule_str)


if __name__ == '__main__':
    unittest.main()
```

- [ ] **Step 2: Run tests to confirm they fail**

```bash
source venv/bin/activate && python -m pytest tests/test_domain_handler_matches.py -v
```

Expected: FAIL — `can_handle('domain_matches')` returns False

- [ ] **Step 3: Update `domain.py`**

Replace the full content of `src/stix2suricata/handlers/domain.py`:

```python
"""Domain name handler"""

from typing import List, Dict
from stix2suricata.handlers.base import BaseHandler
from stix2suricata.core.rule import SuricataRule


class DomainHandler(BaseHandler):
    """Handler for domain name indicators (exact match and regex MATCHES)"""

    def can_handle(self, indicator_type: str) -> bool:
        return indicator_type in ('domain', 'domain_matches')

    def handle(self, indicator: Dict, config=None) -> List[SuricataRule]:
        if indicator['type'] == 'domain_matches':
            return self._handle_matches(indicator)
        return self._handle_exact(indicator)

    def _handle_exact(self, indicator: Dict) -> List[SuricataRule]:
        """Convert exact domain indicator to Suricata DNS content rule"""
        value = indicator['value']
        metadata = indicator.get('stix_metadata', {})

        threat_type = "Suspicious domain"
        if metadata.get('labels'):
            threat_type = metadata['labels'][0]

        options = self.get_default_options(f"STIX IOC - {threat_type} - Domain {value}")
        options.insert(1, f'dns.query; content:"{value}"; nocase')

        return [SuricataRule(protocol="dns", options=options)]

    def _handle_matches(self, indicator: Dict) -> List[SuricataRule]:
        """Convert MATCHES domain indicator to Suricata DNS pcre rule"""
        value = indicator['value']
        metadata = indicator.get('stix_metadata', {})

        msg = metadata.get('name', 'Suspicious Domain Pattern')
        tactic = metadata.get('tactic', '')
        classtype = self._tactic_to_classtype(tactic)
        pcre = self._regex_to_pcre(value)

        options = [
            f'msg:"{msg}"',
            f'dns.query; pcre:"{pcre}"',
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

        return [SuricataRule(protocol="dns", options=options)]
```

- [ ] **Step 4: Run tests to confirm they pass**

```bash
source venv/bin/activate && python -m pytest tests/test_domain_handler_matches.py tests/test_converter.py -v
```

Expected: all pass

- [ ] **Step 5: Commit**

```bash
git add src/stix2suricata/handlers/domain.py tests/test_domain_handler_matches.py
git commit -m "feat: extend DomainHandler to generate pcre rules for domain_matches indicators"
```

---

## Task 6: Implement `OCABundleParser`

**Files:**
- Create: `src/stix2suricata/core/oca_parser.py`
- Test: `tests/test_oca_parser.py`

- [ ] **Step 1: Write the failing tests**

Create `tests/test_oca_parser.py`:

```python
import unittest
import base64
from stix2suricata.core.oca_parser import OCABundleParser

# Minimal OCA bundle: one detection + one behavior + one detects relationship
LFI_PATTERN_B64 = base64.b64encode(b"[url:value MATCHES '.*etc/passwd.*']").decode()

SAMPLE_BUNDLE = {
    "type": "bundle",
    "objects": [
        {
            "type": "x-oca-behavior",
            "id": "x-oca-behavior--43c42191-87ee-4545-88b6-cad87e14cb1b",
            "name": "LFI - /etc/passwd access",
            "description": "Local file inclusion on a vulnerable web server",
            "technique": "T1190",
            "tactic": "TA0001",
        },
        {
            "type": "x-oca-detection",
            "id": "x-oca-detection--74a81dee-43b9-43b8-9b94-949e9b39a6e0",
            "name": "Wazuh Detection for LFI - /etc/passwd access",
            "analytic": {
                "rule": LFI_PATTERN_B64,
                "type": "Stix Pattern"
            }
        },
        {
            "type": "relationship",
            "id": "relationship--36221057-9cc9-4d77-8543-9b2286138402",
            "relationship_type": "detects",
            "source_ref": "x-oca-detection--74a81dee-43b9-43b8-9b94-949e9b39a6e0",
            "target_ref": "x-oca-behavior--43c42191-87ee-4545-88b6-cad87e14cb1b"
        }
    ]
}

BUNDLE_NO_BEHAVIOR = {
    "type": "bundle",
    "objects": [
        {
            "type": "x-oca-detection",
            "id": "x-oca-detection--orphan",
            "name": "Orphan Detection",
            "analytic": {"rule": LFI_PATTERN_B64, "type": "Stix Pattern"}
        }
    ]
}

BUNDLE_BAD_BASE64 = {
    "type": "bundle",
    "objects": [
        {
            "type": "x-oca-detection",
            "id": "x-oca-detection--bad",
            "name": "Bad Detection",
            "analytic": {"rule": "not-valid-base64!!!", "type": "Stix Pattern"}
        }
    ]
}

BUNDLE_UNSUPPORTED_TYPE = {
    "type": "bundle",
    "objects": [
        {
            "type": "x-oca-detection",
            "id": "x-oca-detection--kql",
            "name": "KQL Detection",
            "analytic": {"rule": LFI_PATTERN_B64, "type": "KQL"}
        }
    ]
}


class TestOCABundleParser(unittest.TestCase):

    def setUp(self):
        self.parser = OCABundleParser()

    def test_returns_indicators_from_oca_bundle(self):
        indicators = self.parser.parse_bundle(SAMPLE_BUNDLE)
        self.assertEqual(len(indicators), 1)

    def test_indicator_type_is_url_matches(self):
        indicators = self.parser.parse_bundle(SAMPLE_BUNDLE)
        self.assertEqual(indicators[0]['type'], 'url_matches')

    def test_indicator_value_is_regex(self):
        indicators = self.parser.parse_bundle(SAMPLE_BUNDLE)
        self.assertEqual(indicators[0]['value'], '.*etc/passwd.*')

    def test_stix_metadata_technique(self):
        indicators = self.parser.parse_bundle(SAMPLE_BUNDLE)
        self.assertEqual(indicators[0]['stix_metadata']['technique'], 'T1190')

    def test_stix_metadata_tactic(self):
        indicators = self.parser.parse_bundle(SAMPLE_BUNDLE)
        self.assertEqual(indicators[0]['stix_metadata']['tactic'], 'TA0001')

    def test_stix_metadata_detection_id(self):
        indicators = self.parser.parse_bundle(SAMPLE_BUNDLE)
        self.assertEqual(
            indicators[0]['stix_metadata']['id'],
            'x-oca-detection--74a81dee-43b9-43b8-9b94-949e9b39a6e0'
        )

    def test_stix_metadata_name(self):
        indicators = self.parser.parse_bundle(SAMPLE_BUNDLE)
        self.assertEqual(
            indicators[0]['stix_metadata']['name'],
            'Wazuh Detection for LFI - /etc/passwd access'
        )

    def test_no_behavior_linked_still_returns_indicator(self):
        indicators = self.parser.parse_bundle(BUNDLE_NO_BEHAVIOR)
        self.assertEqual(len(indicators), 1)

    def test_no_behavior_linked_has_no_technique(self):
        indicators = self.parser.parse_bundle(BUNDLE_NO_BEHAVIOR)
        self.assertNotIn('technique', indicators[0]['stix_metadata'])

    def test_bad_base64_skips_detection(self):
        indicators = self.parser.parse_bundle(BUNDLE_BAD_BASE64)
        self.assertEqual(len(indicators), 0)

    def test_unsupported_analytic_type_skips_detection(self):
        indicators = self.parser.parse_bundle(BUNDLE_UNSUPPORTED_TYPE)
        self.assertEqual(len(indicators), 0)

    def test_empty_bundle_returns_empty_list(self):
        indicators = self.parser.parse_bundle({"type": "bundle", "objects": []})
        self.assertEqual(indicators, [])

    def test_non_oca_objects_ignored(self):
        bundle = {
            "type": "bundle",
            "objects": [
                {"type": "identity", "id": "identity--abc", "name": "Test"},
                {"type": "extension-definition", "id": "extension-definition--abc"},
            ]
        }
        indicators = self.parser.parse_bundle(bundle)
        self.assertEqual(indicators, [])


if __name__ == '__main__':
    unittest.main()
```

- [ ] **Step 2: Run tests to confirm they fail**

```bash
source venv/bin/activate && python -m pytest tests/test_oca_parser.py -v
```

Expected: FAIL — `ModuleNotFoundError: No module named 'stix2suricata.core.oca_parser'`

- [ ] **Step 3: Create `oca_parser.py`**

Create `src/stix2suricata/core/oca_parser.py`:

```python
"""OCA bundle parser for x-oca-detection / x-oca-behavior objects"""

import base64
import logging
from typing import List, Dict

from stix2suricata.core.parser import StixPatternParser


class OCABundleParser:
    """Parses OCA extension bundles into indicator dicts for the existing pipeline.

    Handles x-oca-detection objects with base64-encoded STIX patterns,
    resolves detects relationships to x-oca-behavior for MITRE metadata.
    """

    def __init__(self):
        self.pattern_parser = StixPatternParser()
        self.logger = logging.getLogger(__name__)

    def parse_bundle(self, bundle: Dict) -> List[Dict]:
        """Parse an OCA bundle and return a list of indicator dicts."""
        objects = bundle.get('objects', [])
        obj_index = {o['id']: o for o in objects if 'id' in o}
        detects_map = self._build_detects_map(objects, obj_index)

        indicators = []
        for obj in objects:
            if obj.get('type') != 'x-oca-detection':
                continue
            parsed = self._parse_detection(obj, detects_map)
            indicators.extend(parsed)

        return indicators

    def _build_detects_map(self, objects: List[Dict], obj_index: Dict) -> Dict:
        """Return {detection_id: behavior_object} from detects relationships."""
        detects_map = {}
        for obj in objects:
            if (obj.get('type') == 'relationship'
                    and obj.get('relationship_type') == 'detects'):
                detection_id = obj.get('source_ref', '')
                behavior_id = obj.get('target_ref', '')
                if behavior_id in obj_index:
                    detects_map[detection_id] = obj_index[behavior_id]
        return detects_map

    def _parse_detection(self, detection: Dict, detects_map: Dict) -> List[Dict]:
        """Parse a single x-oca-detection object into indicator dicts."""
        analytic = detection.get('analytic', {})
        if analytic.get('type') != 'Stix Pattern':
            self.logger.warning(
                "Skipping detection %s: unsupported analytic type '%s'",
                detection.get('id'), analytic.get('type')
            )
            return []

        pattern = self._decode_pattern(detection)
        if pattern is None:
            return []

        behavior = detects_map.get(detection.get('id', ''))
        stix_metadata = self._build_metadata(detection, behavior)

        indicators = self.pattern_parser.parse(pattern)
        for indicator in indicators:
            indicator['stix_metadata'] = stix_metadata
        return indicators

    def _decode_pattern(self, detection: Dict):
        """Base64-decode the analytic.rule field. Returns None on error."""
        rule_b64 = detection.get('analytic', {}).get('rule', '')
        try:
            return base64.b64decode(rule_b64).decode('utf-8')
        except Exception as exc:
            self.logger.warning(
                "Skipping detection %s: base64 decode error: %s",
                detection.get('id'), exc
            )
            return None

    def _build_metadata(self, detection: Dict, behavior) -> Dict:
        """Build the stix_metadata dict from detection and optional behavior."""
        metadata = {
            'id': detection.get('id', ''),
            'name': detection.get('name', ''),
        }
        if behavior:
            metadata['technique'] = behavior.get('technique', '')
            metadata['tactic'] = behavior.get('tactic', '')
            metadata['description'] = behavior.get('description', '')
        return metadata
```

- [ ] **Step 4: Run tests to confirm they pass**

```bash
source venv/bin/activate && python -m pytest tests/test_oca_parser.py -v
```

Expected: all pass

- [ ] **Step 5: Run full suite to check for regressions**

```bash
source venv/bin/activate && python -m pytest tests/ -v
```

Expected: all pass

- [ ] **Step 6: Commit**

```bash
git add src/stix2suricata/core/oca_parser.py tests/test_oca_parser.py
git commit -m "feat: add OCABundleParser for x-oca-detection/x-oca-behavior bundles"
```

---

## Task 7: Wire auto-detection into `StixConverter` and add integration test

**Files:**
- Modify: `src/stix2suricata/core/converter.py`
- Test: `tests/test_converter_oca.py`

- [ ] **Step 1: Write the failing integration test**

Create `tests/test_converter_oca.py`:

```python
import unittest
import base64
from stix2suricata import StixConverter
from stix2suricata.utils.config import Config

LFI_B64 = base64.b64encode(b"[url:value MATCHES '.*etc/passwd.*']").decode()
NMAP_B64 = base64.b64encode(b"[process:command_line MATCHES '(?i)nmap']").decode()

OCA_BUNDLE = {
    "type": "bundle",
    "objects": [
        {
            "type": "x-oca-behavior",
            "id": "x-oca-behavior--43c42191-87ee-4545-88b6-cad87e14cb1b",
            "name": "LFI - /etc/passwd access",
            "description": "Local file inclusion on a vulnerable web server",
            "technique": "T1190",
            "tactic": "TA0001",
        },
        {
            "type": "x-oca-detection",
            "id": "x-oca-detection--74a81dee-43b9-43b8-9b94-949e9b39a6e0",
            "name": "Wazuh Detection for LFI - /etc/passwd access",
            "analytic": {"rule": LFI_B64, "type": "Stix Pattern"}
        },
        {
            "type": "relationship",
            "id": "relationship--aaaaaaaa",
            "relationship_type": "detects",
            "source_ref": "x-oca-detection--74a81dee-43b9-43b8-9b94-949e9b39a6e0",
            "target_ref": "x-oca-behavior--43c42191-87ee-4545-88b6-cad87e14cb1b"
        },
        {
            "type": "x-oca-behavior",
            "id": "x-oca-behavior--41548ef4-379a-46bc-8959-c6990b1727a7",
            "name": "Network Port Scan",
            "description": "Nmap scan",
            "technique": "T1046",
            "tactic": "TA0007",
        },
        {
            "type": "x-oca-detection",
            "id": "x-oca-detection--3e50100d-01a3-4cd1-9b8e-e4c655dd6486",
            "name": "Wazuh Detection for Network Port Scan",
            "analytic": {"rule": NMAP_B64, "type": "Stix Pattern"}
        },
        {
            "type": "relationship",
            "id": "relationship--bbbbbbbb",
            "relationship_type": "detects",
            "source_ref": "x-oca-detection--3e50100d-01a3-4cd1-9b8e-e4c655dd6486",
            "target_ref": "x-oca-behavior--41548ef4-379a-46bc-8959-c6990b1727a7"
        },
    ]
}


class TestConverterOCA(unittest.TestCase):

    def setUp(self):
        self.converter = StixConverter(config=Config(), starting_sid=5000000)
        self.converter.register_default_handlers()

    def test_oca_bundle_generates_rules(self):
        rules = self.converter.convert_bundle(OCA_BUNDLE)
        # LFI → 1 rule; nmap (process:command_line) → 0 rules (skipped)
        self.assertEqual(len(rules), 1)

    def test_lfi_rule_contains_pcre(self):
        rules = self.converter.convert_bundle(OCA_BUNDLE)
        self.assertIn('pcre:', rules[0])

    def test_lfi_rule_contains_etc_passwd(self):
        rules = self.converter.convert_bundle(OCA_BUNDLE)
        self.assertIn('etc\\/passwd', rules[0])

    def test_lfi_rule_contains_mitre_technique(self):
        rules = self.converter.convert_bundle(OCA_BUNDLE)
        self.assertIn('mitre_technique T1190', rules[0])

    def test_lfi_rule_contains_mitre_tactic(self):
        rules = self.converter.convert_bundle(OCA_BUNDLE)
        self.assertIn('mitre_tactic TA0001', rules[0])

    def test_lfi_rule_contains_classtype(self):
        rules = self.converter.convert_bundle(OCA_BUNDLE)
        self.assertIn('web-application-attack', rules[0])

    def test_lfi_rule_contains_rev(self):
        rules = self.converter.convert_bundle(OCA_BUNDLE)
        self.assertIn('rev:1', rules[0])

    def test_lfi_rule_contains_sid(self):
        rules = self.converter.convert_bundle(OCA_BUNDLE)
        self.assertIn('sid:5000000', rules[0])

    def test_standard_bundle_still_works(self):
        standard_bundle = {
            "type": "bundle",
            "objects": [
                {
                    "type": "indicator",
                    "id": "indicator--aaa",
                    "pattern": "[ipv4-addr:value = '1.2.3.4']",
                    "labels": ["malicious-activity"],
                    "name": "Bad IP",
                    "created": "2025-01-01T00:00:00Z",
                    "modified": "2025-01-01T00:00:00Z",
                }
            ]
        }
        rules = self.converter.convert_bundle(standard_bundle)
        self.assertEqual(len(rules), 1)
        self.assertIn('1.2.3.4', rules[0])


if __name__ == '__main__':
    unittest.main()
```

- [ ] **Step 2: Run tests to confirm they fail**

```bash
source venv/bin/activate && python -m pytest tests/test_converter_oca.py -v
```

Expected: FAIL — `AssertionError: 0 != 1` (converter doesn't know about OCA bundles yet)

- [ ] **Step 3: Update `converter.py`**

Add the import at the top of `src/stix2suricata/core/converter.py`:

```python
from stix2suricata.core.oca_parser import OCABundleParser
```

Then replace the `convert_bundle` method:

```python
def convert_bundle(self, bundle: Dict) -> List[str]:
    """Convert STIX bundle to Suricata rules.

    Auto-detects OCA bundles (containing x-oca-detection objects)
    and routes them to OCABundleParser; standard STIX bundles use
    the regular StixPatternParser.
    """
    objects = bundle.get('objects', [])
    if any(o.get('type') == 'x-oca-detection' for o in objects):
        indicators = OCABundleParser().parse_bundle(bundle)
    else:
        indicators = self.parser.parse_bundle(bundle)

    rules = []
    for indicator in indicators:
        rule_strings = self.convert_indicator(indicator)
        rules.extend(rule_strings)
    return rules
```

- [ ] **Step 4: Run the full test suite**

```bash
source venv/bin/activate && python -m pytest tests/ -v
```

Expected: all pass. Output should look like:

```
tests/test_base_handler.py::TestBaseHandlerHelpers::test_pcre_... PASSED
...
tests/test_converter.py::TestConverter::test_domain_conversion PASSED
tests/test_converter.py::TestConverter::test_ipv4_conversion PASSED
tests/test_converter.py::TestConverter::test_url_conversion PASSED
tests/test_converter_oca.py::TestConverterOCA::test_lfi_rule_contains_... PASSED
...
tests/test_domain_handler_matches.py::... PASSED
...
tests/test_oca_parser.py::... PASSED
...
tests/test_parser_matches.py::... PASSED
...
tests/test_rule.py::... PASSED
...
tests/test_url_handler_matches.py::... PASSED
```

- [ ] **Step 5: Commit**

```bash
git add src/stix2suricata/core/converter.py tests/test_converter_oca.py
git commit -m "feat: auto-detect OCA bundles in StixConverter.convert_bundle"
```

---

## Self-Review Checklist

- [x] **rev:1** — Task 1
- [x] **_regex_to_pcre()** — Task 2
- [x] **_tactic_to_classtype()** — Task 2
- [x] **MATCHES patterns in parser** — Task 3
- [x] **url_matches → pcre rule** — Task 4
- [x] **domain_matches → pcre rule** — Task 5
- [x] **OCABundleParser** — Task 6
- [x] **auto-detection in convert_bundle()** — Task 7
- [x] **process_command_line skipped with warning** — covered by existing `convert_indicator()` warning path; tested implicitly in `test_oca_bundle_generates_rules` (nmap returns 0 rules)
- [x] **bad base64 → warning + skip** — Task 6 test
- [x] **unsupported analytic type → warning + skip** — Task 6 test
- [x] **no behavior linked → indicator still produced, no MITRE fields** — Task 6 test
- [x] **standard STIX bundles unaffected** — Task 7 regression test
