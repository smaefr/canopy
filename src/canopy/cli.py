from __future__ import annotations

import argparse
import sys
from pathlib import Path

from canopy import __version__
from canopy.engine import scan_path
from canopy.models import Severity
from canopy.report import SUPPORTED_FORMATS, render
from canopy.rules import all_rules


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="canopy",
        description="Scan Java, C, and C++ source for common vulnerability patterns.",
    )
    parser.add_argument("--version", action="version", version=f"canopy {__version__}")
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan = subparsers.add_parser("scan", help="scan a file or directory")
    scan.add_argument("path", type=Path, help="file or directory to scan")
    scan.add_argument(
        "--format",
        choices=SUPPORTED_FORMATS,
        default="text",
        help="output format (default: text)",
    )
    scan.add_argument(
        "--severity",
        choices=[item.name.lower() for item in Severity],
        default="low",
        help="minimum severity to report (default: low)",
    )
    scan.add_argument(
        "--lang",
        choices=["java", "c", "cpp"],
        help="treat every file as this language instead of using the extension",
    )

    subparsers.add_parser("rules", help="list built-in rules")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "rules":
        return _print_rules()
    return _scan(args)


def _scan(args: argparse.Namespace) -> int:
    try:
        findings = scan_path(args.path, lang=args.lang)
    except FileNotFoundError as exc:
        print(f"canopy: path not found: {exc}", file=sys.stderr)
        return 2

    floor = Severity.parse(args.severity)
    reported = [item for item in findings if item.severity >= floor]
    sys.stdout.write(render(reported, args.format))
    return 1 if reported else 0


def _print_rules() -> int:
    rules = all_rules()
    if not rules:
        return 0
    width = max(len(rule.id) for rule in rules)
    for rule in rules:
        languages = ",".join(rule.languages)
        print(
            f"{rule.id:<{width}}  {rule.severity!s:<6}  {rule.cwe:<8}  "
            f"{languages:<10}  {rule.message}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
