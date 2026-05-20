# Directory Watcher Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a `stix2suricata watch` subcommand that monitors a directory for `peer-*.json` OCA IoB bundle files, converts them to Suricata rules, and POSTs each rule to a remote HTTP endpoint — never sending the same rule twice, surviving restarts via a JSON state file.

**Architecture:** Three focused classes in a new `watcher/` package — `WatcherState` (state persistence), `RuleSender` (HTTP POST with retry/backoff), `DirectoryWatcher` (polling loop that orchestrates the others). The existing `StixConverter.convert_bundle()` already auto-detects OCA bundles, so no changes to the conversion pipeline. Rule deduplication uses SHA256 of rule content with the `sid:N;` field stripped, making hashes stable across restarts.

**Tech Stack:** Python 3.12, `requests` (new dep), `pytest` with `tmp_path` and `unittest.mock`, existing `stix2suricata` package.

---

## File Map

| Action | File | Responsibility |
|--------|------|---------------|
| Create | `src/stix2suricata/watcher/__init__.py` | Package marker |
| Create | `src/stix2suricata/watcher/state.py` | `WatcherState` — load/save processed filenames and sent rule hashes |
| Create | `src/stix2suricata/watcher/sender.py` | `RuleSender` — POST rule JSON with exponential-backoff retry |
| Create | `src/stix2suricata/watcher/watcher.py` | `DirectoryWatcher` — polling loop, file scanning, rule hashing |
| Modify | `src/stix2suricata/cli.py` | Add `watch` subcommand routing |
| Modify | `requirements.txt` | Add `requests>=2.28` |
| Create | `tests/watcher/__init__.py` | Test package marker |
| Create | `tests/watcher/test_state.py` | Tests for `WatcherState` |
| Create | `tests/watcher/test_sender.py` | Tests for `RuleSender` |
| Create | `tests/watcher/test_watcher.py` | Tests for `DirectoryWatcher` |
| Create | `tests/watcher/test_cli_watch.py` | Tests for CLI `watch` subcommand |

---

## Task 1: Bootstrap — `requests` dependency and package skeleton

**Files:**
- Modify: `requirements.txt`
- Create: `src/stix2suricata/watcher/__init__.py`
- Create: `tests/watcher/__init__.py`

- [ ] **Step 1: Add `requests` to requirements.txt**

The full updated `requirements.txt`:

```
pyyaml>=6.0
stix2-patterns>=2.0.0
colorama>=0.4.6
requests>=2.28
```

- [ ] **Step 2: Install the new dependency**

```bash
source venv/bin/activate && pip install requests -q
```

Expected: installs without errors

- [ ] **Step 3: Create empty package files**

Create `src/stix2suricata/watcher/__init__.py` (empty file):

```python
```

Create `tests/watcher/__init__.py` (empty file):

```python
```

- [ ] **Step 4: Verify import works**

```bash
source venv/bin/activate && python -c "import requests; print('OK')"
```

Expected: `OK`

- [ ] **Step 5: Run existing tests to confirm baseline**

```bash
source venv/bin/activate && python -m pytest tests/ -v 2>&1 | tail -5
```

Expected: `64 passed`

- [ ] **Step 6: Commit**

```bash
git add requirements.txt src/stix2suricata/watcher/__init__.py tests/watcher/__init__.py
git commit -m "chore: add requests dependency and watcher package skeleton"
```

---

## Task 2: `WatcherState`

**Files:**
- Create: `src/stix2suricata/watcher/state.py`
- Create: `tests/watcher/test_state.py`

- [ ] **Step 1: Write the failing tests**

Create `tests/watcher/test_state.py`:

```python
import json
import pytest
from stix2suricata.watcher.state import WatcherState


def make_state(tmp_path):
    return WatcherState(str(tmp_path / '.watcher_state.json'))


def test_load_creates_empty_state_if_file_missing(tmp_path):
    state = make_state(tmp_path)
    state.load()
    assert not state.is_processed('peer-001.json')
    assert not state.is_sent('abc123')


def test_mark_processed_and_check(tmp_path):
    state = make_state(tmp_path)
    state.load()
    state.mark_processed('peer-001.json')
    assert state.is_processed('peer-001.json')
    assert not state.is_processed('peer-002.json')


def test_mark_sent_and_check(tmp_path):
    state = make_state(tmp_path)
    state.load()
    state.mark_sent('abc123')
    assert state.is_sent('abc123')
    assert not state.is_sent('xyz789')


def test_save_and_reload_roundtrip(tmp_path):
    path = str(tmp_path / '.watcher_state.json')
    state = WatcherState(path)
    state.load()
    state.mark_processed('peer-001.json')
    state.mark_sent('abc123')
    state.save()

    state2 = WatcherState(path)
    state2.load()
    assert state2.is_processed('peer-001.json')
    assert state2.is_sent('abc123')
    assert not state2.is_processed('peer-002.json')
    assert not state2.is_sent('xyz789')


def test_save_is_atomic_no_tmp_left(tmp_path):
    state = make_state(tmp_path)
    state.load()
    state.mark_processed('peer-001.json')
    state.save()
    assert not (tmp_path / '.watcher_state.json.tmp').exists()
    assert (tmp_path / '.watcher_state.json').exists()


def test_save_produces_valid_json(tmp_path):
    path = str(tmp_path / '.watcher_state.json')
    state = WatcherState(path)
    state.load()
    state.mark_processed('peer-001.json')
    state.mark_sent('deadbeef')
    state.save()
    with open(path) as f:
        data = json.load(f)
    assert 'peer-001.json' in data['processed']
    assert 'deadbeef' in data['sent_hashes']


def test_load_existing_state(tmp_path):
    path = str(tmp_path / '.watcher_state.json')
    data = {'processed': ['peer-001.json'], 'sent_hashes': ['aabbcc']}
    with open(path, 'w') as f:
        json.dump(data, f)

    state = WatcherState(path)
    state.load()
    assert state.is_processed('peer-001.json')
    assert state.is_sent('aabbcc')
```

- [ ] **Step 2: Run to confirm failure**

```bash
source venv/bin/activate && python -m pytest tests/watcher/test_state.py -v
```

Expected: FAIL — `ModuleNotFoundError: No module named 'stix2suricata.watcher.state'`

- [ ] **Step 3: Implement `state.py`**

Create `src/stix2suricata/watcher/state.py`:

```python
"""Watcher state — persists processed filenames and sent rule hashes across restarts."""

import json
import os
from typing import Set


class WatcherState:
    """Loads and saves the set of processed files and sent rule hashes."""

    def __init__(self, state_file: str):
        self.state_file = state_file
        self._processed: Set[str] = set()
        self._sent_hashes: Set[str] = set()

    def load(self) -> None:
        """Load state from disk. Creates empty state if file does not exist."""
        if not os.path.exists(self.state_file):
            return
        with open(self.state_file, 'r', encoding='utf-8') as f:
            data = json.load(f)
        self._processed = set(data.get('processed', []))
        self._sent_hashes = set(data.get('sent_hashes', []))

    def save(self) -> None:
        """Atomically write state to disk via a temp file + rename."""
        tmp = self.state_file + '.tmp'
        data = {
            'processed': sorted(self._processed),
            'sent_hashes': sorted(self._sent_hashes),
        }
        with open(tmp, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2)
        os.replace(tmp, self.state_file)

    def is_processed(self, filename: str) -> bool:
        return filename in self._processed

    def mark_processed(self, filename: str) -> None:
        self._processed.add(filename)

    def is_sent(self, rule_hash: str) -> bool:
        return rule_hash in self._sent_hashes

    def mark_sent(self, rule_hash: str) -> None:
        self._sent_hashes.add(rule_hash)
```

- [ ] **Step 4: Run tests to confirm they pass**

```bash
source venv/bin/activate && python -m pytest tests/watcher/test_state.py -v
```

Expected: 7 passed

- [ ] **Step 5: Commit**

```bash
git add src/stix2suricata/watcher/state.py tests/watcher/test_state.py
git commit -m "feat: add WatcherState for persistent processed/sent tracking"
```

---

## Task 3: `RuleSender`

**Files:**
- Create: `src/stix2suricata/watcher/sender.py`
- Create: `tests/watcher/test_sender.py`

- [ ] **Step 1: Write the failing tests**

Create `tests/watcher/test_sender.py`:

```python
import pytest
import requests as req
from unittest.mock import MagicMock, patch, call
from stix2suricata.watcher.sender import RuleSender

RULE = 'alert http any any -> any any (msg:"LFI"; sid:5000000; rev:1;)'
SOURCE = 'peer-001.json'
ENDPOINT = 'http://192.168.1.10/suricataRule'


def make_sender(max_retries=3):
    return RuleSender(ENDPOINT, max_retries=max_retries, timeout=10)


def mock_resp(status_code, text=''):
    r = MagicMock()
    r.status_code = status_code
    r.text = text
    return r


def test_send_returns_true_on_200():
    sender = make_sender()
    with patch('requests.post', return_value=mock_resp(200)):
        assert sender.send(RULE, SOURCE) is True


def test_send_returns_true_on_201():
    sender = make_sender()
    with patch('requests.post', return_value=mock_resp(201)):
        assert sender.send(RULE, SOURCE) is True


def test_send_posts_correct_payload():
    sender = make_sender()
    with patch('requests.post', return_value=mock_resp(200)) as mock_post:
        sender.send(RULE, SOURCE)
    mock_post.assert_called_once_with(
        ENDPOINT,
        json={'rule': RULE, 'source_file': SOURCE},
        timeout=10,
    )


def test_send_returns_false_on_400_no_retry():
    sender = make_sender()
    with patch('requests.post', return_value=mock_resp(400, 'Bad Request')) as mock_post:
        result = sender.send(RULE, SOURCE)
    assert result is False
    assert mock_post.call_count == 1


def test_send_returns_false_on_404_no_retry():
    sender = make_sender()
    with patch('requests.post', return_value=mock_resp(404)) as mock_post:
        result = sender.send(RULE, SOURCE)
    assert result is False
    assert mock_post.call_count == 1


def test_send_retries_on_500():
    sender = make_sender(max_retries=3)
    with patch('requests.post', return_value=mock_resp(500)) as mock_post:
        with patch('time.sleep'):
            result = sender.send(RULE, SOURCE)
    assert result is False
    assert mock_post.call_count == 3


def test_send_retries_on_connection_error():
    sender = make_sender(max_retries=3)
    with patch('requests.post', side_effect=req.ConnectionError('refused')) as mock_post:
        with patch('time.sleep'):
            result = sender.send(RULE, SOURCE)
    assert result is False
    assert mock_post.call_count == 3


def test_send_succeeds_on_second_attempt():
    sender = make_sender(max_retries=3)
    responses = [mock_resp(503), mock_resp(200)]
    with patch('requests.post', side_effect=responses):
        with patch('time.sleep'):
            result = sender.send(RULE, SOURCE)
    assert result is True


def test_send_backoff_sleep_durations():
    """After attempt 0 sleep 2s, after attempt 1 sleep 4s, no sleep after last."""
    sender = make_sender(max_retries=3)
    sleep_calls = []
    with patch('requests.post', return_value=mock_resp(503)):
        with patch('time.sleep', side_effect=lambda s: sleep_calls.append(s)):
            sender.send(RULE, SOURCE)
    assert sleep_calls == [2, 4]


def test_send_timeout_triggers_retry():
    sender = make_sender(max_retries=3)
    with patch('requests.post', side_effect=req.Timeout('timed out')) as mock_post:
        with patch('time.sleep'):
            result = sender.send(RULE, SOURCE)
    assert result is False
    assert mock_post.call_count == 3
```

- [ ] **Step 2: Run to confirm failure**

```bash
source venv/bin/activate && python -m pytest tests/watcher/test_sender.py -v
```

Expected: FAIL — `ModuleNotFoundError: No module named 'stix2suricata.watcher.sender'`

- [ ] **Step 3: Implement `sender.py`**

Create `src/stix2suricata/watcher/sender.py`:

```python
"""HTTP rule sender with exponential-backoff retry."""

import logging
import time

import requests

logger = logging.getLogger(__name__)


class RuleSender:
    """POSTs a single Suricata rule to an HTTP endpoint.

    Retries on 5xx / network errors with exponential backoff (2s, 4s, …).
    Returns False immediately on 4xx (client errors are not retried).
    """

    def __init__(self, endpoint: str, max_retries: int = 3, timeout: int = 10):
        self.endpoint = endpoint
        self.max_retries = max_retries
        self.timeout = timeout

    def send(self, rule: str, source_file: str) -> bool:
        """Send a rule to the endpoint. Returns True on success, False otherwise."""
        payload = {'rule': rule, 'source_file': source_file}

        for attempt in range(self.max_retries):
            try:
                resp = requests.post(self.endpoint, json=payload, timeout=self.timeout)

                if resp.status_code < 300:
                    return True

                if resp.status_code < 500:
                    logger.warning(
                        "Client error %d sending rule from %s: %s",
                        resp.status_code, source_file, resp.text[:200],
                    )
                    return False

                logger.warning(
                    "Server error %d (attempt %d/%d)",
                    resp.status_code, attempt + 1, self.max_retries,
                )

            except requests.RequestException as exc:
                logger.warning(
                    "Request failed (attempt %d/%d): %s",
                    attempt + 1, self.max_retries, exc,
                )

            if attempt < self.max_retries - 1:
                time.sleep(2 ** (attempt + 1))

        logger.warning(
            "Giving up sending rule from %s after %d attempts",
            source_file, self.max_retries,
        )
        return False
```

- [ ] **Step 4: Run tests to confirm they pass**

```bash
source venv/bin/activate && python -m pytest tests/watcher/test_sender.py -v
```

Expected: 11 passed

- [ ] **Step 5: Commit**

```bash
git add src/stix2suricata/watcher/sender.py tests/watcher/test_sender.py
git commit -m "feat: add RuleSender with exponential-backoff retry"
```

---

## Task 4: `DirectoryWatcher`

**Files:**
- Create: `src/stix2suricata/watcher/watcher.py`
- Create: `tests/watcher/test_watcher.py`

- [ ] **Step 1: Write the failing tests**

Create `tests/watcher/test_watcher.py`:

```python
import base64
import json
import pytest
from unittest.mock import MagicMock, patch
from stix2suricata.watcher.watcher import DirectoryWatcher

# Minimal OCA IoB bundle that generates exactly one URL pcre rule
LFI_B64 = base64.b64encode(b"[url:value MATCHES '.*etc/passwd.*']").decode()

OCA_BUNDLE = {
    "type": "bundle",
    "objects": [
        {
            "type": "x-oca-behavior",
            "id": "x-oca-behavior--aaa",
            "name": "LFI",
            "technique": "T1190",
            "tactic": "TA0001",
            "description": "Local file inclusion",
        },
        {
            "type": "x-oca-detection",
            "id": "x-oca-detection--bbb",
            "name": "LFI Detection",
            "analytic": {"rule": LFI_B64, "type": "Stix Pattern"},
        },
        {
            "type": "relationship",
            "id": "relationship--ccc",
            "relationship_type": "detects",
            "source_ref": "x-oca-detection--bbb",
            "target_ref": "x-oca-behavior--aaa",
        },
    ],
}


def make_watcher(tmp_path, endpoint='http://localhost/suricataRule'):
    return DirectoryWatcher(
        watch_dir=str(tmp_path),
        endpoint=endpoint,
        interval=1,
        sid_start=5000000,
    )


# --- _rule_hash ---

def test_rule_hash_strips_sid():
    h1 = DirectoryWatcher._rule_hash('alert http any any (sid:100; rev:1;)')
    h2 = DirectoryWatcher._rule_hash('alert http any any (sid:999; rev:1;)')
    assert h1 == h2


def test_rule_hash_differs_for_different_content():
    h1 = DirectoryWatcher._rule_hash('alert http any any (msg:"A"; sid:1; rev:1;)')
    h2 = DirectoryWatcher._rule_hash('alert http any any (msg:"B"; sid:1; rev:1;)')
    assert h1 != h2


def test_rule_hash_is_deterministic():
    rule = 'alert http any any (msg:"test"; sid:42; rev:1;)'
    assert DirectoryWatcher._rule_hash(rule) == DirectoryWatcher._rule_hash(rule)


# --- run() ---

def test_run_raises_if_dir_missing(tmp_path):
    watcher = make_watcher(tmp_path / 'nonexistent')
    with pytest.raises(FileNotFoundError):
        watcher.run()


# --- _scan() ---

def test_processes_new_peer_file(tmp_path):
    (tmp_path / 'peer-001.json').write_text(json.dumps(OCA_BUNDLE), encoding='utf-8')
    watcher = make_watcher(tmp_path)
    watcher.sender = MagicMock()
    watcher.sender.send.return_value = True
    watcher._scan()
    assert watcher.sender.send.called
    assert watcher.state.is_processed('peer-001.json')


def test_ignores_files_not_matching_peer_prefix(tmp_path):
    (tmp_path / 'other.json').write_text(json.dumps(OCA_BUNDLE), encoding='utf-8')
    (tmp_path / 'bundle-001.json').write_text(json.dumps(OCA_BUNDLE), encoding='utf-8')
    watcher = make_watcher(tmp_path)
    watcher.sender = MagicMock()
    watcher._scan()
    assert not watcher.sender.send.called


def test_skips_already_processed_file(tmp_path):
    (tmp_path / 'peer-001.json').write_text(json.dumps(OCA_BUNDLE), encoding='utf-8')
    watcher = make_watcher(tmp_path)
    watcher.state.mark_processed('peer-001.json')
    watcher.sender = MagicMock()
    watcher._scan()
    assert not watcher.sender.send.called


def test_skips_already_sent_rule_on_retry(tmp_path):
    (tmp_path / 'peer-001.json').write_text(json.dumps(OCA_BUNDLE), encoding='utf-8')
    watcher = make_watcher(tmp_path)
    watcher.sender = MagicMock()
    watcher.sender.send.return_value = True

    watcher._scan()
    assert watcher.sender.send.call_count == 1

    # Simulate retry: remove from processed but keep sent_hashes
    watcher.state._processed.discard('peer-001.json')
    watcher.sender.send.reset_mock()
    watcher._scan()

    # Rule hash already in sent_hashes — not sent again
    assert watcher.sender.send.call_count == 0
    # But file is marked processed (all rules accounted for)
    assert watcher.state.is_processed('peer-001.json')


def test_file_not_marked_processed_if_send_fails(tmp_path):
    (tmp_path / 'peer-001.json').write_text(json.dumps(OCA_BUNDLE), encoding='utf-8')
    watcher = make_watcher(tmp_path)
    watcher.sender = MagicMock()
    watcher.sender.send.return_value = False
    watcher._scan()
    assert not watcher.state.is_processed('peer-001.json')


def test_malformed_json_marked_processed(tmp_path):
    (tmp_path / 'peer-bad.json').write_text('not-valid-json!!!', encoding='utf-8')
    watcher = make_watcher(tmp_path)
    watcher.sender = MagicMock()
    watcher._scan()
    assert watcher.state.is_processed('peer-bad.json')
    assert not watcher.sender.send.called


def test_bundle_with_no_rules_marked_processed(tmp_path):
    empty_bundle = {'type': 'bundle', 'objects': []}
    (tmp_path / 'peer-empty.json').write_text(json.dumps(empty_bundle), encoding='utf-8')
    watcher = make_watcher(tmp_path)
    watcher.sender = MagicMock()
    watcher._scan()
    assert watcher.state.is_processed('peer-empty.json')
    assert not watcher.sender.send.called


def test_state_saved_to_disk_after_scan(tmp_path):
    (tmp_path / 'peer-001.json').write_text(json.dumps(OCA_BUNDLE), encoding='utf-8')
    watcher = make_watcher(tmp_path)
    watcher.sender = MagicMock()
    watcher.sender.send.return_value = True
    watcher._scan()
    assert (tmp_path / '.watcher_state.json').exists()


def test_default_state_file_in_watch_dir(tmp_path):
    watcher = make_watcher(tmp_path)
    expected = str(tmp_path / '.watcher_state.json')
    assert watcher.state_file == expected


def test_multiple_files_processed_in_order(tmp_path):
    for i in range(3):
        (tmp_path / f'peer-00{i}.json').write_text(json.dumps(OCA_BUNDLE), encoding='utf-8')
    watcher = make_watcher(tmp_path)
    watcher.sender = MagicMock()
    watcher.sender.send.return_value = True
    watcher._scan()
    assert watcher.state.is_processed('peer-000.json')
    assert watcher.state.is_processed('peer-001.json')
    assert watcher.state.is_processed('peer-002.json')
```

- [ ] **Step 2: Run to confirm failure**

```bash
source venv/bin/activate && python -m pytest tests/watcher/test_watcher.py -v
```

Expected: FAIL — `ModuleNotFoundError: No module named 'stix2suricata.watcher.watcher'`

- [ ] **Step 3: Implement `watcher.py`**

Create `src/stix2suricata/watcher/watcher.py`:

```python
"""Directory watcher — polls for peer-*.json OCA bundles and forwards rules via HTTP."""

import glob
import hashlib
import json
import logging
import os
import re
import time

from stix2suricata import StixConverter
from stix2suricata.utils.config import Config
from stix2suricata.watcher.sender import RuleSender
from stix2suricata.watcher.state import WatcherState

logger = logging.getLogger(__name__)


class DirectoryWatcher:
    """Polls a directory for new peer-*.json OCA bundles and sends generated rules via HTTP."""

    def __init__(
        self,
        watch_dir: str,
        endpoint: str,
        interval: int = 5,
        state_file: str = None,
        max_retries: int = 3,
        sid_start: int = 5000000,
    ):
        self.watch_dir = watch_dir
        self.endpoint = endpoint
        self.interval = interval
        self.state_file = state_file or os.path.join(watch_dir, '.watcher_state.json')
        self.max_retries = max_retries
        self.sid_start = sid_start
        self.state = WatcherState(self.state_file)
        self.sender = RuleSender(endpoint, max_retries=max_retries)

    def run(self) -> None:
        """Block and poll indefinitely. Handles KeyboardInterrupt cleanly."""
        if not os.path.isdir(self.watch_dir):
            raise FileNotFoundError(f"Watch directory does not exist: {self.watch_dir}")

        self.state.load()
        logger.info(
            "Watching %s for peer-*.json files every %ds → %s",
            self.watch_dir, self.interval, self.endpoint,
        )

        try:
            while True:
                self._scan()
                time.sleep(self.interval)
        except KeyboardInterrupt:
            logger.info("Interrupted — saving state and exiting")
            self.state.save()

    def _scan(self) -> None:
        """One polling cycle: find new files, process each, save state."""
        pattern = os.path.join(self.watch_dir, 'peer-*.json')
        files = sorted(glob.glob(pattern))

        for filepath in files:
            filename = os.path.basename(filepath)
            if self.state.is_processed(filename):
                continue
            self._process_file(filepath, filename)

        self.state.save()

    def _process_file(self, filepath: str, filename: str) -> None:
        """Parse a bundle file, convert to rules, send each one."""
        logger.info("Processing %s", filename)

        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                bundle = json.load(f)
        except (json.JSONDecodeError, OSError) as exc:
            logger.warning("Skipping %s: JSON parse error: %s", filename, exc)
            self.state.mark_processed(filename)
            return

        converter = StixConverter(config=Config(), starting_sid=self.sid_start)
        converter.register_default_handlers()
        rules = converter.convert_bundle(bundle)

        if not rules:
            logger.info("No rules generated from %s", filename)
            self.state.mark_processed(filename)
            return

        all_sent = True
        for rule in rules:
            rule_hash = self._rule_hash(rule)
            if self.state.is_sent(rule_hash):
                logger.debug("Rule already sent, skipping")
                continue
            if self.sender.send(rule, filename):
                self.state.mark_sent(rule_hash)
            else:
                all_sent = False

        if all_sent:
            self.state.mark_processed(filename)
            logger.info("Processed %s: %d rule(s) forwarded", filename, len(rules))

    @staticmethod
    def _rule_hash(rule: str) -> str:
        """SHA256 of rule content with sid:N; stripped — stable across SID counter resets."""
        normalized = re.sub(r'sid:\d+;', '', rule)
        return hashlib.sha256(normalized.encode()).hexdigest()
```

- [ ] **Step 4: Run tests to confirm they pass**

```bash
source venv/bin/activate && python -m pytest tests/watcher/test_watcher.py -v
```

Expected: 14 passed

- [ ] **Step 5: Run full suite to check for regressions**

```bash
source venv/bin/activate && python -m pytest tests/ -v 2>&1 | tail -5
```

Expected: all pass (64 + new watcher tests)

- [ ] **Step 6: Commit**

```bash
git add src/stix2suricata/watcher/watcher.py tests/watcher/test_watcher.py
git commit -m "feat: add DirectoryWatcher polling loop with rule deduplication"
```

---

## Task 5: CLI `watch` subcommand

**Files:**
- Modify: `src/stix2suricata/cli.py`
- Create: `tests/watcher/test_cli_watch.py`

- [ ] **Step 1: Write the failing tests**

Create `tests/watcher/test_cli_watch.py`:

```python
import pytest
from unittest.mock import patch, MagicMock


def run_cli(args):
    """Run cli.main() with the given sys.argv list (excluding script name)."""
    import sys
    from stix2suricata.cli import main
    with patch.object(sys, 'argv', ['stix2suricata'] + args):
        return main()


def test_watch_requires_dir(capsys):
    with pytest.raises(SystemExit) as exc:
        run_cli(['watch', '--endpoint', 'http://localhost/suricataRule'])
    assert exc.value.code != 0


def test_watch_requires_endpoint(capsys):
    with pytest.raises(SystemExit) as exc:
        run_cli(['watch', '--dir', '/tmp'])
    assert exc.value.code != 0


def test_watch_calls_directory_watcher(tmp_path):
    mock_watcher = MagicMock()
    with patch('stix2suricata.cli.DirectoryWatcher', return_value=mock_watcher) as MockDW:
        run_cli([
            'watch',
            '--dir', str(tmp_path),
            '--endpoint', 'http://192.168.1.10/suricataRule',
        ])
    MockDW.assert_called_once_with(
        watch_dir=str(tmp_path),
        endpoint='http://192.168.1.10/suricataRule',
        interval=5,
        state_file=None,
        max_retries=3,
        sid_start=5000000,
    )
    mock_watcher.run.assert_called_once()


def test_watch_passes_custom_interval(tmp_path):
    mock_watcher = MagicMock()
    with patch('stix2suricata.cli.DirectoryWatcher', return_value=mock_watcher) as MockDW:
        run_cli([
            'watch',
            '--dir', str(tmp_path),
            '--endpoint', 'http://localhost/suricataRule',
            '--interval', '10',
        ])
    assert MockDW.call_args.kwargs['interval'] == 10


def test_watch_passes_custom_retries(tmp_path):
    mock_watcher = MagicMock()
    with patch('stix2suricata.cli.DirectoryWatcher', return_value=mock_watcher) as MockDW:
        run_cli([
            'watch',
            '--dir', str(tmp_path),
            '--endpoint', 'http://localhost/suricataRule',
            '--retries', '5',
        ])
    assert MockDW.call_args.kwargs['max_retries'] == 5


def test_watch_passes_custom_state_file(tmp_path):
    mock_watcher = MagicMock()
    state_path = str(tmp_path / 'custom.json')
    with patch('stix2suricata.cli.DirectoryWatcher', return_value=mock_watcher) as MockDW:
        run_cli([
            'watch',
            '--dir', str(tmp_path),
            '--endpoint', 'http://localhost/suricataRule',
            '--state-file', state_path,
        ])
    assert MockDW.call_args.kwargs['state_file'] == state_path


def test_watch_passes_sid_start(tmp_path):
    mock_watcher = MagicMock()
    with patch('stix2suricata.cli.DirectoryWatcher', return_value=mock_watcher) as MockDW:
        run_cli([
            'watch',
            '--dir', str(tmp_path),
            '--endpoint', 'http://localhost/suricataRule',
            '--sid-start', '9000000',
        ])
    assert MockDW.call_args.kwargs['sid_start'] == 9000000


def test_existing_convert_mode_unaffected():
    """Existing -p flag must still work after adding watch subcommand."""
    with patch('stix2suricata.cli.StixConverter') as MockConv:
        mock_conv_instance = MagicMock()
        mock_conv_instance.convert_pattern.return_value = ["alert ip any any -> any any (sid:1; rev:1;)"]
        MockConv.return_value = mock_conv_instance
        run_cli(['-p', "[ipv4-addr:value = '1.2.3.4']"])
    mock_conv_instance.convert_pattern.assert_called_once()
```

- [ ] **Step 2: Run to confirm failure**

```bash
source venv/bin/activate && python -m pytest tests/watcher/test_cli_watch.py -v
```

Expected: FAIL — `test_watch_calls_directory_watcher` fails because `watch` is not a recognized command

- [ ] **Step 3: Update `cli.py`**

Replace the full content of `src/stix2suricata/cli.py`:

```python
"""Command-line interface"""

import argparse
import json
import sys
import logging

from stix2suricata import StixConverter
from stix2suricata.utils.config import Config
from stix2suricata.utils.logger import setup_logging
from stix2suricata.watcher.watcher import DirectoryWatcher


def main():
    """Main CLI entry point. Routes to 'watch' subcommand or legacy convert mode."""
    if len(sys.argv) > 1 and sys.argv[1] == 'watch':
        _watch_command(sys.argv[2:])
    else:
        _convert_command()


def _watch_command(argv):
    """Handle 'stix2suricata watch ...' subcommand."""
    parser = argparse.ArgumentParser(
        prog='stix2suricata watch',
        description='Monitor a directory for peer-*.json OCA bundles and forward Suricata rules via HTTP',
    )
    parser.add_argument(
        '--dir', required=True,
        help='Directory to monitor for peer-*.json files',
    )
    parser.add_argument(
        '--endpoint', required=True,
        help='HTTP endpoint URL, e.g. http://192.168.1.10/suricataRule',
    )
    parser.add_argument(
        '--interval', type=int, default=5,
        help='Polling interval in seconds (default: 5)',
    )
    parser.add_argument(
        '--state-file', default=None,
        help='State file path (default: <dir>/.watcher_state.json)',
    )
    parser.add_argument(
        '--retries', type=int, default=3,
        help='Max HTTP retries per rule (default: 3)',
    )
    parser.add_argument(
        '--sid-start', type=int, default=5000000,
        help='Starting SID for rule generation (default: 5000000)',
    )
    parser.add_argument(
        '-v', '--verbose', action='store_true',
        help='Verbose output',
    )

    args = parser.parse_args(argv)
    log_level = 'DEBUG' if args.verbose else 'INFO'
    setup_logging(log_level)

    watcher = DirectoryWatcher(
        watch_dir=args.dir,
        endpoint=args.endpoint,
        interval=args.interval,
        state_file=args.state_file,
        max_retries=args.retries,
        sid_start=args.sid_start,
    )
    watcher.run()


def _convert_command():
    """Handle legacy 'stix2suricata -i file.json' / '-p pattern' modes."""
    parser = argparse.ArgumentParser(
        description='Convert STIX 2.x patterns to Suricata/Snort rules',
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument('-i', '--input', help='Input STIX bundle JSON file')
    parser.add_argument('-o', '--output', help='Output Suricata rules file')
    parser.add_argument('-p', '--pattern', help='Single STIX pattern to convert')
    parser.add_argument('--sid-start', type=int, default=5000000,
                        help='Starting SID number (default: 5000000)')
    parser.add_argument('-c', '--config', help='Configuration file path')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')

    args = parser.parse_args()

    log_level = 'DEBUG' if args.verbose else 'INFO'
    setup_logging(log_level)
    logger = logging.getLogger(__name__)

    config = Config(args.config) if args.config else Config()
    converter = StixConverter(config=config, starting_sid=args.sid_start)
    converter.register_default_handlers()

    rules = []

    try:
        if args.pattern:
            logger.info("Converting pattern: %s", args.pattern)
            rules = converter.convert_pattern(args.pattern)

        elif args.input:
            logger.info("Reading STIX bundle from: %s", args.input)
            with open(args.input, 'r', encoding='utf-8') as f:
                bundle = json.load(f)
            rules = converter.convert_bundle(bundle)

        else:
            parser.print_help()
            sys.exit(1)

        if not rules:
            logger.warning("No rules generated")
            sys.exit(0)

        if args.output:
            converter.save_rules(rules, args.output)
            logger.info("Saved %d rules to %s", len(rules), args.output)
        else:
            print("\n# Generated Suricata Rules\n")
            for rule in rules:
                print(rule)

        logger.info("Successfully generated %d rules", len(rules))

    except Exception as e:
        logger.error("Error: %s", e, exc_info=args.verbose)
        sys.exit(1)


if __name__ == '__main__':
    main()
```

- [ ] **Step 4: Run tests to confirm they pass**

```bash
source venv/bin/activate && python -m pytest tests/watcher/test_cli_watch.py -v
```

Expected: 8 passed

- [ ] **Step 5: Run full suite**

```bash
source venv/bin/activate && python -m pytest tests/ -v 2>&1 | tail -10
```

Expected: all pass

- [ ] **Step 6: Smoke test the CLI manually**

```bash
source venv/bin/activate && stix2suricata watch --help
```

Expected output includes `--dir`, `--endpoint`, `--interval`, `--retries`, `--state-file`.

```bash
source venv/bin/activate && stix2suricata -p "[ipv4-addr:value = '1.2.3.4']"
```

Expected: prints a Suricata rule with the IP address (existing behavior unbroken).

- [ ] **Step 7: Commit**

```bash
git add src/stix2suricata/cli.py tests/watcher/test_cli_watch.py
git commit -m "feat: add watch subcommand to CLI for directory monitoring"
```

---

## Self-Review Checklist

- [x] **`requests>=2.28` in requirements.txt** — Task 1
- [x] **`watcher/__init__.py` + `tests/watcher/__init__.py`** — Task 1
- [x] **`WatcherState.load/save/is_processed/mark_processed/is_sent/mark_sent`** — Task 2
- [x] **Atomic save via `.tmp` + `os.replace`** — Task 2
- [x] **`RuleSender.send` — 2xx success, 4xx no-retry, 5xx/timeout retry with 2s/4s backoff** — Task 3
- [x] **`DirectoryWatcher._rule_hash` — strips `sid:N;` before SHA256** — Task 4
- [x] **`DirectoryWatcher._scan` — `peer-*.json` glob, skips processed files** — Task 4
- [x] **`DirectoryWatcher._process_file` — malformed JSON → mark processed; no rules → mark processed; partial send failure → don't mark processed** — Task 4
- [x] **Already-sent rule hashes skipped on retry** — Task 4 (`test_skips_already_sent_rule_on_retry`)
- [x] **State saved to disk after every scan cycle** — Task 4
- [x] **`DirectoryWatcher.run` — loads state, polls loop, Ctrl-C saves state and exits** — Task 4
- [x] **`watch` subcommand with all required args (`--dir`, `--endpoint`, `--interval`, `--state-file`, `--retries`, `--sid-start`)** — Task 5
- [x] **Existing `-i`/`-p` convert mode unaffected** — Task 5 (`test_existing_convert_mode_unaffected`)
- [x] **Missing `--dir` or `--endpoint` → exit non-zero** — Task 5
- [x] **Fatal error if watch dir does not exist at startup** — Task 4 (`test_run_raises_if_dir_missing`)