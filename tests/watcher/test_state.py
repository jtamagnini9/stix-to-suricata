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