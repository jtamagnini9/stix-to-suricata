import pytest
import requests as req
from unittest.mock import MagicMock, patch
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
    """After attempt 0 sleep 2s, after attempt 1 sleep 4s, no sleep after last attempt."""
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