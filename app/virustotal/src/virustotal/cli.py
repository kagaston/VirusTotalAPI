"""Command-line interface for the VirusTotal API client."""

import argparse
import sys

from errors.handler import handle_error
from logger.config import get_logger, setup_logging
from settings.config import VIRUSTOTAL_API_KEY
from virustotal.client import VirusTotalClient

log = get_logger("cli")


def main(argv: list[str] | None = None) -> None:
    """Entry point for the CLI.

    Args:
        argv: Command-line arguments (defaults to sys.argv[1:]).
    """
    setup_logging("vt")

    parser = argparse.ArgumentParser(description="VirusTotal API Client")
    subparsers = parser.add_subparsers(dest="command")

    file_scan_parser = subparsers.add_parser("file-scan", help="Submit a file for scanning")
    file_scan_parser.add_argument("file_path", help="Path to the file")

    url_scan_parser = subparsers.add_parser("url-scan", help="Submit a URL for scanning")
    url_scan_parser.add_argument("url", help="URL to scan")

    ip_report_parser = subparsers.add_parser("ip-report", help="Retrieve IP address report")
    ip_report_parser.add_argument("ip_address", help="IP address")

    domain_report_parser = subparsers.add_parser("domain-report", help="Retrieve domain report")
    domain_report_parser.add_argument("domain", help="Domain")

    args = parser.parse_args(argv)

    if not args.command:
        parser.print_help()
        sys.exit(1)

    if not VIRUSTOTAL_API_KEY:
        log.error("VIRUSTOTAL_API_KEY is not set")
        sys.exit(1)

    client = VirusTotalClient(VIRUSTOTAL_API_KEY)

    commands = {
        "file-scan": lambda: client.file_scan(args.file_path),
        "url-scan": lambda: client.url_scan(args.url),
        "ip-report": lambda: client.ip_report(args.ip_address),
        "domain-report": lambda: client.domain_report(args.domain),
    }

    try:
        result = commands[args.command]()
        log.info(result)
        print(result)  # noqa: T201
    except Exception as exc:
        msg = handle_error(exc, context=args.command)
        print(msg, file=sys.stderr)  # noqa: T201
        sys.exit(1)


if __name__ == "__main__":
    main()
