from __future__ import annotations

import argparse
import json
import sys

from . import __version__
from .redaction import sanitize


DESCRIPTION = (
    "AutoDev v2: passive repository alignment. Generated drafts do not enable execution."
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
    commands = parser.add_subparsers(dest="command")
    init = commands.add_parser("init", help="preview conservative repository alignment", allow_abbrev=False)
    init.add_argument("repo")
    init.add_argument("--dry-run", action="store_true")
    init.add_argument("--json", action="store_true")
    init.add_argument("--yes", action="store_true")
    init.add_argument("--apply", metavar="PROPOSAL_DIGEST")
    init.add_argument("--recover", action="store_true")
    init.add_argument("--project")
    init.add_argument("--name")
    init.add_argument("--slug")
    init.add_argument("--select", action="append", default=[], metavar="CATEGORY=PATH")
    init.add_argument("--worktree-bucket")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command == "init":
        return _init(args, parser)
    parser.print_help()
    return 0


def _emit(report: dict, *, json_mode: bool) -> None:
    # One canonical envelope is shared by JSON and the reviewable text preview.
    displayed = sanitize(report)
    if displayed != report:
        displayed["display_redacted"] = True
    print(json.dumps(displayed, sort_keys=True, separators=(",", ":") if json_mode else None,
                     ensure_ascii=True, allow_nan=False))


def _exit_code(status: str) -> int:
    if status in {"preview", "noop", "applied", "recovered", "clean"}:
        return 0
    if status in {"failed", "recovery_required"}:
        return 1
    return 2


def _init(args: argparse.Namespace, parser: argparse.ArgumentParser) -> int:
    if (args.dry_run and (args.yes or args.apply or args.recover)
            or args.recover and args.apply
            or args.apply and not args.yes
            or args.json and args.yes and not (args.apply or args.recover)
            or args.recover and not args.yes):
        parser.error("incompatible init review/apply flags")
    # Lazy imports preserve the import/help effect boundary.
    from .init.proposal import build_proposal

    options = dict(selections=tuple(args.select), project=args.project,
                   name=args.name, slug=args.slug, worktree_bucket=args.worktree_bucket)
    proposal = build_proposal(args.repo, **options)
    report = proposal.to_dict()
    if args.recover:
        if args.json:
            _emit({"status": "needs_input", "proposal": report,
                   "diagnostics": [{"code": "recovery_text_review_required",
                                    "action": "Run init <repo> --recover --yes in text mode to review the recovery diff before mutation."}]},
                  json_mode=True)
            return 2
        from .init.apply import recover_repository
        _emit(report, json_mode=False)
        outcome = recover_repository(proposal.root).to_dict()
        _emit({"proposal": report, **outcome}, json_mode=args.json)
        return _exit_code(outcome["status"])

    interactive = not args.json and sys.stdin.isatty()
    # An explicit numbered response is the only interactive ambiguity resolution.
    if interactive and proposal.status == "needs_input":
        choices = report.get("unresolved", [])
        selected = list(args.select)
        selected_project = args.project
        for choice in choices:
            if not isinstance(choice, dict):
                continue
            category = choice.get("category")
            candidates = choice.get("candidates", [])
            if not category or not candidates:
                continue
            print(f"Select {category}:")
            for index, candidate in enumerate(candidates, 1):
                print(f"  {index}. {sanitize(candidate)}")
            try:
                answer = input("Choice (empty cancels): ").strip()
            except EOFError:
                break
            if not answer.isdecimal() or not 1 <= int(answer) <= len(candidates):
                break
            chosen = candidates[int(answer) - 1]
            if category == "project":
                selected_project = chosen
            else:
                selected.append(f"{category}={chosen}")
        if selected != args.select or selected_project != args.project:
            options["selections"] = tuple(selected)
            options["project"] = selected_project
            proposal = build_proposal(args.repo, **options)
            report = proposal.to_dict()

    if proposal.status not in {"preview", "noop"}:
        _emit(report, json_mode=args.json)
        return _exit_code(proposal.status)
    if not args.json:
        _emit(report, json_mode=False)
    apply_digest = args.apply
    if args.yes and not args.json and not apply_digest:
        apply_digest = proposal.digest
    elif interactive and not args.dry_run and not apply_digest and proposal.status != "noop":
        try:
            accepted = input("Apply these exact alignment changes? [y/N] ").strip().lower() == "y"
        except EOFError:
            accepted = False
        if accepted:
            apply_digest = proposal.digest
    if apply_digest:
        from .init.apply import apply_proposal
        outcome = apply_proposal(proposal, expected_digest=apply_digest,
                                 recompute=lambda: build_proposal(args.repo, **options)).to_dict()
        _emit({"proposal": report, **outcome}, json_mode=args.json)
        return _exit_code(outcome["status"])
    if args.json:
        _emit(report, json_mode=True)
    return _exit_code(proposal.status)
