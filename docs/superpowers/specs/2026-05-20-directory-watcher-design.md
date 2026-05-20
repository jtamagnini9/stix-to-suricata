# Directory Watcher — Design Spec

**Date:** 2026-05-20
**Status:** Approved

## Problem

The existing CLI converts a single STIX/OCA JSON file on demand. Resilmesh needs a continuous process that monitors a directory for incoming IoB bundle files (`peer-*.json`), converts them to Suricata rules, and pushes each rule to a remote HTTP endpoint — without ever sending the same rule twice.

## Scope

- New `watch` subcommand added to the existing `stix2suricata` CLI
- Monitor a directory for files matching `peer-*.json`
- Parse each file as an OCA IoB bundle (via existing `StixConverter.convert_bundle()` auto-detection)
- POST each generated rule individually to `<endpoint>/suricataRule`
- Track processed files and sent rules across restarts via a JSON state file
- Retry failed HTTP sends with exponential backoff; never re-send a rule that was already delivered
- No new dependencies except `requests`

## Architecture

### New files

| File | Purpose |
|------|---------|
| `src/stix2suricata/watcher/__init__.py` | Package marker |
| `src/stix2suricata/watcher/state.py` | `WatcherState` — load/save processed files and sent rule hashes |
| `src/stix2suricata/watcher/sender.py` | `RuleSender` — HTTP POST with retry/backoff |
| `src/stix2suricata/watcher/watcher.py` | `DirectoryWatcher` — polling loop that orchestrates the others |

### Modified files

| File | Change |
|------|--------|
| `src/stix2suricata/cli.py` | Add `watch` subcommand |
| `requirements.txt` | Add `requests>=2.28` |

### Data flow

```
stix2suricata watch --dir /path --endpoint http://ip/suricataRule
        │
        ▼
DirectoryWatcher.run()  [loop every --interval seconds]
  │
  ├─ glob("peer-*.json") in --dir
  ├─ filter out files already in WatcherState.processed
  │
  └─ for each new file:
       ├─ json.load() → StixConverter.convert_bundle()  [auto-detects OCA]
       ├─ all_sent = True
       │
       └─ for each rule in rules:
            ├─ hash = SHA256(rule with sid:\d+; stripped)
            ├─ if hash in WatcherState.sent_hashes → skip (already sent)
            └─ RuleSender.send(rule, source_file)
                 ├─ success (2xx) → WatcherState.sent_hashes.add(hash)
                 ├─ client error (4xx) → WARNING log, skip, all_sent = False
                 └─ server error / timeout → retry up to max_retries
                      └─ still fails → WARNING log, skip, all_sent = False
       │
       └─ if all_sent → WatcherState.processed.add(filename)
  │
  └─ WatcherState.save()  [at end of each cycle]
```

## Component Details

### `WatcherState` (`state.py`)

```python
class WatcherState:
    def __init__(self, state_file: str): ...
    def load(self) -> None: ...           # reads JSON from disk, creates empty if missing
    def save(self) -> None: ...           # writes JSON to disk atomically
    def is_processed(self, filename: str) -> bool: ...
    def mark_processed(self, filename: str) -> None: ...
    def is_sent(self, rule_hash: str) -> bool: ...
    def mark_sent(self, rule_hash: str) -> None: ...
```

State file format (`<dir>/.watcher_state.json` by default):
```json
{
  "processed": ["peer-001.json", "peer-002.json"],
  "sent_hashes": ["a3f2c1...", "b8e4d2..."]
}
```

Atomic save: write to `<state_file>.tmp` then rename, to avoid corruption on crash.

### `RuleSender` (`sender.py`)

```python
class RuleSender:
    def __init__(self, endpoint: str, max_retries: int = 3, timeout: int = 10): ...
    def send(self, rule: str, source_file: str) -> bool: ...
```

- POST `{"rule": "...", "source_file": "..."}` with `Content-Type: application/json`
- Returns `True` on 2xx
- Returns `False` immediately on 4xx (client error, no retry)
- Retries on 5xx / `requests.RequestException` with `2^attempt` second backoff (2s, 4s after first failure)
- Logs WARNING after exhausting retries

### `DirectoryWatcher` (`watcher.py`)

```python
class DirectoryWatcher:
    def __init__(
        self,
        watch_dir: str,
        endpoint: str,
        interval: int = 5,
        state_file: str = None,    # defaults to <watch_dir>/.watcher_state.json
        max_retries: int = 3,
        sid_start: int = 5000000,
    ): ...
    def run(self) -> None: ...     # blocks; handles KeyboardInterrupt gracefully
```

Rule hash computation:
```python
import re, hashlib
def _rule_hash(rule: str) -> str:
    normalized = re.sub(r'sid:\d+;', '', rule)
    return hashlib.sha256(normalized.encode()).hexdigest()
```

### CLI — `watch` subcommand (`cli.py`)

```
stix2suricata watch
  --dir PATH            Directory to monitor (required)
  --endpoint URL        HTTP endpoint URL (required), e.g. http://192.168.1.10/suricataRule
  --interval N          Polling interval in seconds (default: 5)
  --state-file PATH     State file path (default: <dir>/.watcher_state.json)
  --retries N           Max HTTP retries per rule (default: 3)
  --sid-start N         Starting SID for rule generation (default: 5000000)
  -v / --verbose        Debug logging
```

## Error Handling

| Situation | Behaviour |
|-----------|-----------|
| `--dir` does not exist at startup | Fatal error, exit 1 |
| File JSON parse error | WARNING log, mark as processed (no retry loop on corrupt files) |
| Bundle generates 0 rules | INFO log, mark as processed |
| HTTP 2xx | Rule hash saved to state |
| HTTP 4xx | WARNING log, skip rule, `all_sent = False` |
| HTTP 5xx / timeout, retries exhausted | WARNING log, skip rule, `all_sent = False` |
| `all_sent = False` for a file | File NOT added to `processed`; retried next cycle |
| Rule hash already in `sent_hashes` | Silently skipped — never re-sent |
| Ctrl-C | State saved, clean exit |

## Deduplication

Rule identity is determined by SHA256 of the rule string with the `sid:N;` field stripped. This makes the hash stable even if the SID counter is reset between runs (e.g., after restart). A rule already delivered to the endpoint is never re-delivered regardless of SID changes.

## Testing

- Unit test `WatcherState`: load/save roundtrip, missing file, `is_processed`, `is_sent`, atomic write
- Unit test `RuleSender`: mock `requests.post` — success (2xx), client error (4xx → no retry), server error (5xx → retries), timeout
- Unit test `DirectoryWatcher._rule_hash`: SID stripping, determinism
- Integration test `DirectoryWatcher`: use `tmp_path`, write a `peer-test.json` OCA bundle, mock `RuleSender.send`, assert state updated correctly
- Test partial failure: first rule sent, second fails → file not in `processed`, first rule hash in `sent_hashes`, second rule retried next cycle

## Out of Scope

- Subdirectory recursion (only top-level `peer-*.json` files)
- HTTPS / mTLS for the endpoint
- Rule deduplication across different source files: the same rule content appearing in two different `peer-*.json` files is sent only once (first occurrence wins); the second file is still marked as fully processed
- Removing entries from `sent_hashes` (state grows indefinitely — acceptable for this use case)
