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
    h1 = DirectoryWatcher._rule_hash('alert http any any (sid:100; rev:1;)', 'peer-001.json')
    h2 = DirectoryWatcher._rule_hash('alert http any any (sid:999; rev:1;)', 'peer-001.json')
    assert h1 == h2


def test_rule_hash_differs_for_different_content():
    h1 = DirectoryWatcher._rule_hash('alert http any any (msg:"A"; sid:1; rev:1;)', 'peer-001.json')
    h2 = DirectoryWatcher._rule_hash('alert http any any (msg:"B"; sid:1; rev:1;)', 'peer-001.json')
    assert h1 != h2


def test_rule_hash_is_deterministic():
    rule = 'alert http any any (msg:"test"; sid:42; rev:1;)'
    assert DirectoryWatcher._rule_hash(rule, 'peer-001.json') == DirectoryWatcher._rule_hash(rule, 'peer-001.json')


def test_rule_hash_differs_for_different_source_file():
    rule = 'alert http any any (msg:"test"; sid:42; rev:1;)'
    h1 = DirectoryWatcher._rule_hash(rule, 'peer-001.json')
    h2 = DirectoryWatcher._rule_hash(rule, 'peer-002.json')
    assert h1 != h2


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