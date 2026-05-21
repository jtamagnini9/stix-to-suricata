"""HTTP rule sender with exponential-backoff retry."""

import base64
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
        payload = {'rule': base64.b64encode(rule.encode()).decode(), 'source_file': source_file}

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