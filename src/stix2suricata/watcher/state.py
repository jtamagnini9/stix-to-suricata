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