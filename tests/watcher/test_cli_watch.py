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