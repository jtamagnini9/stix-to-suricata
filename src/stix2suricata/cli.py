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
