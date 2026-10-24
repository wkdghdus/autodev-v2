from __future__ import annotations

import os
import sys
import tempfile
import textwrap
import unittest
from importlib import import_module
from pathlib import Path
from unittest import mock


class IndependentAD02RegressionTests(unittest.TestCase):
    def test_nested_lock_acquisition_rejects_lower_level_after_account_lock(self) -> None:
        try:
            locks = import_module("autodev.safety.locks")
        except ModuleNotFoundError:
            self.fail("autodev.safety.locks is required for AD-02 lock ordering")
        from autodev.safety.types import LockError

        with tempfile.TemporaryDirectory(dir="/private/tmp") as tmp:
            root = Path(tmp) / "state"
            root.mkdir(mode=0o700)
            with locks.account_lock(root, "acct-a", owner_identity="owner"):
                with self.assertRaises(LockError):
                    with locks.installation_lock(root, "install-a", owner_identity="owner"):
                        pass

    def test_runner_rejects_invalid_output_limit_before_child_side_effects(self) -> None:
        try:
            runner = import_module("autodev.safety.runner")
        except ModuleNotFoundError:
            self.fail("autodev.safety.runner is required for AD-02 command execution")

        with tempfile.TemporaryDirectory(dir="/private/tmp") as tmp:
            script = "print('must not spawn')"
            with self.assertRaises(ValueError):
                with mock.patch(
                    "subprocess.Popen",
                    side_effect=AssertionError("runner spawned before validating byte limits"),
                ):
                    runner.run_command(
                        runner.CommandRequest(
                            argv=(sys.executable, "-B", "-c", script),
                            cwd=tmp,
                            max_stdout_bytes=-1,
                        )
                    )

    def test_runner_diagnostics_redact_canary_embedded_in_cwd(self) -> None:
        try:
            runner = import_module("autodev.safety.runner")
        except ModuleNotFoundError:
            self.fail("autodev.safety.runner is required for AD-02 command execution")

        canary = "AD02-CWD-CANARY-secret"
        with tempfile.TemporaryDirectory(dir="/private/tmp") as tmp:
            cwd = Path(tmp) / canary
            cwd.mkdir()
            result = runner.run_command(
                runner.CommandRequest(
                    argv=(sys.executable, "-B", "-c", "print('ok')"),
                    cwd=cwd,
                    canaries=(canary,),
                )
            )
            self.assertNotIn(canary, str(result.diagnostics()))

    def test_passive_git_refuses_linked_gitdir_before_supported_reads(self) -> None:
        try:
            git_status_porcelain = import_module("autodev.safety.git_read").git_status_porcelain
        except ModuleNotFoundError:
            self.fail("autodev.safety.git_read is required for passive Git inspection")
        with tempfile.TemporaryDirectory(dir="/private/tmp") as tmp:
            tmp_path = Path(tmp)
            repo = tmp_path / "repo"
            repo.mkdir()
            external_gitdir = tmp_path / "external-git"
            external_gitdir.mkdir()
            (repo / ".git").write_text(f"gitdir: {external_gitdir}\n", encoding="utf-8")
            calls: list[tuple[str, ...]] = []

            def runner(request: object) -> object:
                from autodev.safety.runner import CommandResult

                argv = tuple(getattr(request, "argv"))
                calls.append(argv)
                return CommandResult(
                    argv=argv,
                    cwd=str(getattr(request, "cwd")),
                    returncode=0,
                    stdout="git version 2.39.5\n",
                    stderr="",
                    stdout_bytes=len("git version 2.39.5\n"),
                    stderr_bytes=0,
                    stdout_truncated=False,
                    stderr_truncated=False,
                    timed_out=False,
                    overflowed=False,
                    killed=False,
                    env_keys=tuple(sorted(getattr(request, "env_overrides"))),
                )

            result = git_status_porcelain(repo, runner=runner)

            self.assertFalse(result.ok)
            self.assertEqual(result.reason, "linked_git_dir_unsupported")
            self.assertEqual(calls, [("git", "--version")])

    def test_journal_corrupt_entry_recovery_preserves_original_identity(self) -> None:
        from autodev.safety.journal import OperationJournal
        from autodev.safety.types import JournalRecovery

        with tempfile.TemporaryDirectory(dir="/private/tmp") as tmp:
            root = Path(tmp) / "state"
            (root / "journal").mkdir(mode=0o700, parents=True)
            journal_path = root / "journal" / "operations.json"
            journal_path.write_text(
                textwrap.dedent(
                    """
                    {
                      "schema_version": 1,
                      "operations": {
                        "idem-original": {
                          "request_digest": "corrupt-digest",
                          "record": {
                            "operation_id": "op-original",
                            "idempotency_key": "idem-original",
                            "operation_state": "PREPARED"
                          }
                        }
                      }
                    }
                    """
                ).strip()
                + "\n",
                encoding="utf-8",
            )
            os.chmod(journal_path, 0o600)

            try:
                recovery = OperationJournal(root).recover("idem-original")
            except Exception as exc:  # noqa: BLE001 - recovery must not leak validator/parser errors.
                self.fail(f"corrupt journal recovery must return JournalRecovery, got {type(exc).__name__}: {exc}")

            self.assertIsInstance(recovery, JournalRecovery)
            self.assertEqual(recovery.status, "CORRUPT")
            self.assertEqual(recovery.operation_id, "op-original")
            self.assertEqual(recovery.idempotency_key, "idem-original")
            self.assertTrue(recovery.native_ids_unknown)


if __name__ == "__main__":
    unittest.main()
