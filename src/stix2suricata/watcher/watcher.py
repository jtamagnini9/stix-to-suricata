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