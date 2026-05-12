# OCA Bundle Support — Design Spec

**Date:** 2026-05-12  
**Status:** Approved

## Problem

The existing converter handles only standard STIX 2.1 `indicator` objects with exact-match patterns (e.g. `[ipv4-addr:value = 'x']`). Resilmesh bundles use OCA extensions (`x-oca-detection`, `x-oca-behavior`) with:

- STIX patterns encoded in base64 inside `analytic.rule`
- The `MATCHES` operator (regex) instead of `=`
- MITRE ATT&CK metadata on the linked behavior object

## Scope

- Parse `x-oca-detection` / `x-oca-behavior` OCA bundles
- Translate `url:value MATCHES` and `domain-name:value MATCHES` patterns to Suricata `pcre` rules
- Enrich generated rules with MITRE technique/tactic metadata
- Skip `process:command_line` patterns with a warning (host-based, not mappable to network rules)
- No changes to the existing standard-STIX pipeline

## Architecture

### New files

| File | Purpose |
|------|---------|
| `src/stix2suricata/core/oca_parser.py` | `OCABundleParser` — parses OCA bundles into indicator dicts |

### Modified files

| File | Change |
|------|--------|
| `src/stix2suricata/core/converter.py` | Auto-detect OCA format in `convert_bundle()` |
| `src/stix2suricata/core/parser.py` | Add `MATCHES` patterns to `StixPatternParser` |
| `src/stix2suricata/handlers/base.py` | Add `_regex_to_pcre()` shared utility |
| `src/stix2suricata/handlers/url.py` | Handle `url_matches` type with pcre |
| `src/stix2suricata/handlers/domain.py` | Handle `domain_matches` type with pcre |
| `src/stix2suricata/core/rule.py` | Add `rev:1` to generated rules |

### Data flow

```
OCA bundle JSON
      │
      ▼
StixConverter.convert_bundle()
      │  detects x-oca-detection → routes to OCABundleParser
      ▼
OCABundleParser.parse_bundle()
      │  1. indexes all objects by id
      │  2. for each x-oca-detection:
      │     - decodes base64 analytic.rule
      │     - follows detects relationship → x-oca-behavior
      │     - extracts technique, tactic, name
      │  3. passes pattern to StixPatternParser.parse()
      │  4. injects stix_metadata into each indicator
      ▼
StixPatternParser.parse()   (existing, + MATCHES support)
      │  url_matches / domain_matches / process_command_line / …
      ▼
StixConverter.convert_indicator()   (existing, unchanged)
      │
      ├─ URLHandler (url_matches)    → http.uri; pcre:...
      ├─ DomainHandler (domain_matches) → dns.query; pcre:...
      └─ unhandled types             → warning, skip
```

## Component Details

### `OCABundleParser`

```python
class OCABundleParser:
    def parse_bundle(self, bundle: dict) -> list[dict]:
        ...
```

Builds an object index, then for each `x-oca-detection` where `analytic.type == "Stix Pattern"`:

1. Base64-decodes `analytic.rule`; skips with warning on decode error
2. Finds the linked `x-oca-behavior` via a `detects` relationship
3. Builds `stix_metadata`:
   ```python
   {
       "id": detection["id"],
       "name": detection["name"],
       "technique": behavior.get("technique", ""),   # e.g. "T1190"
       "tactic":    behavior.get("tactic", ""),      # e.g. "TA0001"
       "description": behavior.get("description", "")
   }
   ```
4. Calls `StixPatternParser().parse(pattern)` and injects metadata into each result

Skips silently (with `logger.warning`) when:
- `analytic.type != "Stix Pattern"`
- base64 decode fails
- no behavior linked (metadata populated with detection fields only — `mitre_technique` and `mitre_tactic` omitted from the Suricata `metadata` keyword)

### `StixPatternParser` — MATCHES extension

New entries in `PATTERNS` dict:

```python
'url_matches':          r"url:value\s+MATCHES\s+'([^']+)'",
'domain_matches':       r"domain-name:value\s+MATCHES\s+'([^']+)'",
'process_command_line': r"process:command_line\s+MATCHES\s+'([^']+)'",
```

Produced indicator dicts use `type: 'url_matches'` etc., value is the raw regex string.

### `BaseHandler._regex_to_pcre(pattern: str) -> str`

Converts a STIX regex string to a Suricata pcre string:

1. Extracts inline `(?i)` flag → appended as `/i`
2. Strips leading/trailing `.*`
3. Escapes `/` → `\/`
4. Returns `"/pattern/flags"`

Example: `'.*etc/passwd.*'` → `"/etc\/passwd/"`, `'(?i)nmap'` → `"/nmap/i"`

### `URLHandler` changes

```python
def can_handle(self, t): return t in ('url', 'url_matches')

def handle(self, indicator, config=None):
    if indicator['type'] == 'url_matches':
        # build pcre rule on http.uri
    else:
        # existing exact-match logic
```

Metadata keyword populated from `stix_metadata` when present:
```
metadata:mitre_technique T1190, mitre_tactic TA0001, stix_id x-oca-detection--74a81dee;
```

### `DomainHandler` changes

Same pattern as `URLHandler`: handles `domain` (existing) and `domain_matches` (new).  
Uses `dns.query; pcre:"/pattern/flags";` for MATCHES.

### Classtype mapping (tactic → Suricata classtype)

| MITRE Tactic | Suricata classtype |
|---|---|
| TA0001 (Initial Access) | `web-application-attack` |
| TA0007 (Discovery) | `network-scan` |
| TA0002 (Execution) | `attempted-admin` |
| TA0040 (Impact) | `denial-of-service` |
| *(fallback)* | `policy-violation` |

### `SuricataRule` — add `rev`

`to_rule()` appends `rev:1` after `sid:N` in the options string. All generated rules get revision 1 by default.

### `StixConverter.convert_bundle()` — auto-detection

```python
def convert_bundle(self, bundle: dict) -> list[str]:
    objects = bundle.get("objects", [])
    if any(o.get("type") == "x-oca-detection" for o in objects):
        indicators = OCABundleParser().parse_bundle(bundle)
    else:
        indicators = self.parser.parse_bundle(bundle)
    # existing pipeline continues unchanged
```

Public API is unchanged.

## Error Handling

| Condition | Behavior |
|-----------|----------|
| `analytic.type != "Stix Pattern"` | `logger.warning`, skip detection |
| base64 decode error | `logger.warning` with detection `id`, skip |
| no `detects` relationship found | use detection metadata only, no MITRE fields |
| unrecognized STIX type (e.g. `process:command_line`) | `logger.warning`, skip indicator |
| invalid regex in MATCHES value | `logger.warning`, skip indicator |

## Testing

- Unit test `OCABundleParser` with the sample bundle from this spec
- Unit test `_regex_to_pcre()` for anchors, flags, escaping
- Unit test `URLHandler` and `DomainHandler` for both `=` and `MATCHES` variants
- Integration test: full bundle → list of rule strings, assert expected pcre content
- Test warning paths: bad base64, missing relationship, unsupported type

## Out of Scope

- Non-STIX analytic types (KQL, Sigma, SPL) — skipped with warning, no conversion
- `network-traffic` MATCHES patterns
- STIX patterns with `AND`/`OR` compound expressions
- Updating/deduplicating existing rule files
