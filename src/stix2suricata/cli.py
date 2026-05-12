"""Command-line interface"""

import argparse
import json
import sys
import logging

from stix2suricata import StixConverter
from stix2suricata.utils.config import Config
from stix2suricata.utils.logger import setup_logging


def main():
    """Main CLI entry point"""
    parser = argparse.ArgumentParser(
        description='Convert STIX 2.x patterns to Suricata/Snort rules',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    parser.add_argument(
        '-i', '--input',
        help='Input STIX bundle JSON file'
    )

    parser.add_argument(
        '-o', '--output',
        help='Output Suricata rules file'
    )

    parser.add_argument(
        '-p', '--pattern',
        help='Single STIX pattern to convert'
    )

    parser.add_argument(
        '--sid-start',
        type=int,
        default=5000000,
        help='Starting SID number (default: 5000000)'
    )

    parser.add_argument(
        '-c', '--config',
        help='Configuration file path'
    )

    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Verbose output'
    )

    args = parser.parse_args()

    # Setup logging
    log_level = 'DEBUG' if args.verbose else 'INFO'
    setup_logging(log_level)
    logger = logging.getLogger(__name__)

    # Load configuration
    config = Config(args.config) if args.config else Config()

    # Initialize converter
    converter = StixConverter(config=config, starting_sid=args.sid_start)
    converter.register_default_handlers()

    rules = []

    try:
        # Process input
        if args.pattern:
            logger.info("Converting pattern: %s", args.pattern)
            rules = converter.convert_pattern(args.pattern)

        elif args.input:
            logger.info("Reading STIX bundle from: %s", {args.input})
            with open(args.input, 'r', encoding='utf-8') as f:
                bundle = json.load(f)
            rules = converter.convert_bundle(bundle)

        else:
            parser.print_help()
            sys.exit(1)

        # Output results
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
