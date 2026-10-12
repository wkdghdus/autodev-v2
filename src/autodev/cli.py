from __future__ import annotations

import argparse

from . import __version__


DESCRIPTION = (
    "AutoDev v2 offline scaffold. AD-00 exposes only import and help; "
    "future live commands are intentionally unavailable."
)


class Parser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        self.print_usage()
        raise SystemExit(2)


def build_parser() -> argparse.ArgumentParser:
    parser = Parser(
        prog="autodev",
        description=DESCRIPTION,
        allow_abbrev=False,
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"autodev {__version__}",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    parser.parse_args(argv)
    parser.print_help()
    return 0
