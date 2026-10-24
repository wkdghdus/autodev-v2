"""Real CLI preview/review/apply behavior without project execution."""
from __future__ import annotations

import contextlib
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from autodev.cli import main


ROOT = Path(__file__).resolve().parents[1]


class InitCLITests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.repo = Path(self.tmp.name).resolve() / "repository with spaces"
        self.repo.mkdir()

    def invoke(self, *args):
        result = subprocess.run(
            [sys.executable, "-B", "-m", "autodev", "init", str(self.repo), *args],
            cwd=ROOT, env={"PATH": "/usr/bin:/bin", "PYTHONPATH": str(ROOT / "src"),
                           "PYTHONDONTWRITEBYTECODE": "1"},
            capture_output=True, text=True, timeout=30, check=False)
        lines = result.stdout.splitlines()
        return result, json.loads(lines[0]) if len(lines) == 1 and lines[0].startswith("{") else None

    def test_preview_apply_then_byte_stable_noop(self):
        preview, report = self.invoke("--json", "--dry-run")
        self.assertEqual(preview.returncode, 0, preview.stderr)
        self.assertEqual(report["status"], "preview")
        self.assertFalse(report["lifecycle_ready"])
        self.assertEqual(list(self.repo.iterdir()), [])
        digest = report.get("digest", report.get("proposal_digest"))
        self.assertIsInstance(digest, str)
        applied, envelope = self.invoke("--json", "--apply", digest, "--yes")
        self.assertEqual(applied.returncode, 0, applied.stdout + applied.stderr)
        self.assertEqual(envelope["status"], "applied")
        self.assertIn("proposal", envelope)
        originals = {path.relative_to(self.repo): path.read_bytes()
                     for path in self.repo.rglob("*") if path.is_file()}
        noop, report = self.invoke("--json")
        self.assertEqual(noop.returncode, 0, noop.stdout + noop.stderr)
        self.assertEqual(report["status"], "noop")
        again, second = self.invoke("--json")
        self.assertEqual(noop.stdout, again.stdout)
        self.assertEqual(originals, {path.relative_to(self.repo): path.read_bytes()
                                    for path in self.repo.rglob("*") if path.is_file()})

    def test_json_requires_explicit_digest_and_yes(self):
        for args in (("--json", "--yes"), ("--apply", "a" * 64),
                     ("--dry-run", "--yes"), ("--recover",),
                     ("--recover", "--apply", "a" * 64, "--yes")):
            result, _ = self.invoke(*args)
            self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
            self.assertEqual(list(self.repo.iterdir()), [])

    def test_json_recovery_demands_visible_review_without_writes(self):
        result, report = self.invoke("--json", "--recover", "--yes")
        self.assertEqual(result.returncode, 2)
        self.assertEqual(report["diagnostics"][0]["code"], "recovery_text_review_required")
        self.assertEqual(list(self.repo.iterdir()), [])

    def test_sensitive_display_metadata_is_redacted_and_marked(self):
        result, report = self.invoke("--json", "--name", "token=AD03-private-display", "--slug", "safe")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertNotIn("AD03-private-display", result.stdout)
        self.assertTrue(report["display_redacted"])
        self.assertEqual(list(self.repo.iterdir()), [])

    def test_stale_digest_does_not_bootstrap(self):
        result, report = self.invoke("--json")
        self.assertEqual(result.returncode, 0)
        (self.repo / "ROADMAP.md").write_text("# Added after preview\n")
        result, envelope = self.invoke("--json", "--apply",
                                       report.get("digest", report.get("proposal_digest")), "--yes")
        self.assertNotEqual(result.returncode, 0)
        self.assertNotEqual(envelope["status"], "applied")
        self.assertFalse((self.repo / ".agent").exists())

    def test_two_roadmaps_need_selection_and_yes_never_selects(self):
        (self.repo / "ROADMAP.md").write_text("# One\n")
        (self.repo / "docs").mkdir()
        (self.repo / "docs" / "ROADMAP.md").write_text("# Two\n")
        for flags in (("--json",), ("--yes",)):
            result, report = self.invoke(*flags)
            self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
            self.assertEqual(report["status"], "needs_input")
            self.assertFalse((self.repo / ".agent").exists())
        result, report = self.invoke("--json", "--select", "execution=ROADMAP.md")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_tty_eof_preserves_repository(self):
        output = io.StringIO()
        with patch("sys.stdin.isatty", return_value=True), patch("builtins.input", side_effect=EOFError), contextlib.redirect_stdout(output):
            code = main(["init", str(self.repo)])
        self.assertEqual(code, 0)
        self.assertEqual(list(self.repo.iterdir()), [])

    def test_tty_numbered_roadmap_choice_remains_preview_when_declined(self):
        (self.repo / "ROADMAP.md").write_text("# One\n")
        (self.repo / "docs").mkdir()
        (self.repo / "docs" / "ROADMAP.md").write_text("# Two\n")
        output = io.StringIO()
        with patch("sys.stdin.isatty", return_value=True), patch("builtins.input", side_effect=["1", "n"]), contextlib.redirect_stdout(output):
            code = main(["init", str(self.repo)])
        self.assertEqual(code, 0, output.getvalue())
        self.assertIn("Select execution", output.getvalue())
        self.assertFalse((self.repo / ".agent").exists())

    def test_text_yes_emits_preview_before_apply(self):
        result, _ = self.invoke("--yes")
        self.assertEqual(result.returncode, 0, result.stderr)
        reports = [json.loads(line) for line in result.stdout.splitlines()]
        self.assertEqual(reports[0]["status"], "preview")
        self.assertEqual(reports[-1]["status"], "applied")


if __name__ == "__main__":
    unittest.main()
