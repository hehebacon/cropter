"""Command-line entry point for CROPTer."""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict

from cropter import __version__
from cropter.scope import load_scope


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="cropter",
        description="CROPTer — authorized vulnerability research toolkit",
    )
    parser.add_argument("--version", action="version", version=f"CROPTer {__version__}")
    subparsers = parser.add_subparsers(dest="command", required=True)
    check = subparsers.add_parser("scope-check", help="check a URL against an explicit scope file")
    check.add_argument("--scope", required=True, help="path to scope file")
    check.add_argument("url", help="URL to check; no network request is made")
    show = subparsers.add_parser("scope-show", help="display parsed scope configuration")
    show.add_argument("--scope", required=True, help="path to scope file")
    return parser


def main() -> int:
    args = build_parser().parse_args()
    try:
        scope = load_scope(args.scope)
        if args.command == "scope-check":
            allowed = scope.allows_url(args.url)
            print(json.dumps({"url": args.url, "in_scope": allowed}, indent=2))
            return 0 if allowed else 2
        if args.command == "scope-show":
            print(json.dumps(asdict(scope), indent=2))
            return 0
    except (OSError, ValueError) as exc:
        print(f"cropter: {exc}", file=sys.stderr)
        return 1
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
