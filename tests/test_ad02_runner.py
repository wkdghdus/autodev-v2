from __future__ import annotations

import os
import signal
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path

from autodev.safety.runner import CommandRequest, run_command


class RunnerTests(unittest.TestCase):
    def test_rejects_shell_string(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(ValueError):
                run_command(CommandRequest(argv="echo unsafe", cwd=tmp))  # type: ignore[arg-type]
            with self.assertRaises(ValueError):
                run_command(CommandRequest(argv=(sys.executable, "-c", "print('late')"), cwd=tmp, max_stdout_bytes=-1))

    def test_redacts_canaries_from_stdout_stderr_and_errors(self) -> None:
        canary = "AD02-RUNNER-CANARY-secret"
        with tempfile.TemporaryDirectory() as tmp:
            script = (
                "import os,sys; "
                "print(os.environ['SECRET_CANARY']); "
                "print('password=' + os.environ['SECRET_CANARY'], file=sys.stderr)"
            )
            result = run_command(
                CommandRequest(
                    argv=(sys.executable, "-B", "-c", script),
                    cwd=tmp,
                    env_overrides={"SECRET_CANARY": canary},
                    canaries=(canary,),
                )
            )
        rendered = str(result.diagnostics())
        self.assertEqual(result.returncode, 0)
        self.assertNotIn(canary, rendered)
        self.assertIn("[REDACTED]", rendered)
        self.assertEqual(result.env_keys, ("LANG", "LC_ALL", "PATH", "SECRET_CANARY"))

    def test_overflow_discards_stream_text_and_reports_counts(self) -> None:
        canary = "AD02-PARTIAL-CANARY"
        with tempfile.TemporaryDirectory() as tmp:
            result = run_command(
                CommandRequest(
                    argv=(sys.executable, "-B", "-c", f"print({canary!r})"),
                    cwd=tmp,
                    max_stdout_bytes=5,
                    canaries=(canary,),
                )
            )
        self.assertTrue(result.stdout_truncated)
        self.assertTrue(result.overflowed)
        self.assertGreater(result.stdout_bytes, 5)
        self.assertEqual(result.stdout, "")
        self.assertNotIn(canary[:5], str(result.diagnostics()))

    @unittest.skipIf(os.name != "posix", "process group assertions require POSIX")
    def test_timeout_kills_process_group_and_reaps_child(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            marker = Path(tmp) / "child.pid"
            script = textwrap.dedent(
                f"""
                import subprocess, sys, time
                child = subprocess.Popen([sys.executable, "-B", "-c", "import time; time.sleep(30)"])
                open({str(marker)!r}, "w", encoding="utf-8").write(str(child.pid))
                time.sleep(30)
                """
            )
            result = run_command(
                CommandRequest(
                    argv=(sys.executable, "-B", "-c", script),
                    cwd=tmp,
                    timeout_seconds=0.3,
                    kill_grace_seconds=0.1,
                )
            )
            self.assertTrue(result.timed_out)
            self.assertTrue(result.killed)
            child_pid = int(marker.read_text(encoding="utf-8"))
            with self.assertRaises(ProcessLookupError):
                os.kill(child_pid, 0)

    @unittest.skipIf(os.name != "posix", "process group assertions require POSIX")
    def test_parent_exit_with_pipe_descendant_is_cleaned_up(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            marker = Path(tmp) / "child.pid"
            script = textwrap.dedent(
                f"""
                import subprocess, sys
                child = subprocess.Popen(
                    [sys.executable, "-B", "-c", "import sys,time; sys.stdout.write('held'); sys.stdout.flush(); time.sleep(30)"],
                    stdout=sys.stdout,
                )
                open({str(marker)!r}, "w", encoding="utf-8").write(str(child.pid))
                """
            )
            result = run_command(
                CommandRequest(
                    argv=(sys.executable, "-B", "-c", script),
                    cwd=tmp,
                    timeout_seconds=1.0,
                    kill_grace_seconds=0.1,
                )
            )
            self.assertTrue(result.killed)
            child_pid = int(marker.read_text(encoding="utf-8"))
            with self.assertRaises(ProcessLookupError):
                os.kill(child_pid, 0)



class RunnerFailureTests(unittest.TestCase):
    def test_errors_and_raw_result_fields_do_not_leak_canaries(self):
        import traceback
        canary = 'COMMAND-EXCEPTION-CANARY'
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(ValueError) as failure:
                run_command(CommandRequest(argv=(str(Path(tmp) / canary),), cwd=tmp, canaries=(canary,)))
            self.assertNotIn(canary, ''.join(traceback.format_exception(failure.exception)))
            result = run_command(CommandRequest(argv=(sys.executable, '-B', '-c', 'pass', canary),
                                                 cwd=tmp, env_overrides={canary: 'safe'}, canaries=(canary,)))
            self.assertNotIn(canary, repr(result))

    def test_invalid_durations_and_types_never_spawn(self):
        from unittest.mock import patch
        from dataclasses import replace
        with tempfile.TemporaryDirectory() as tmp:
            request = CommandRequest((sys.executable, '-B', '-c', 'pass'), tmp)
            for changes in ({'timeout_seconds': float('nan')}, {'timeout_seconds': float('inf')},
                            {'timeout_seconds': 0}, {'kill_grace_seconds': -1},
                            {'max_stdout_bytes': True}, {'max_stderr_bytes': 1.5}):
                with self.subTest(changes=changes), patch('subprocess.Popen') as spawn:
                    with self.assertRaises(ValueError):
                        run_command(replace(request, **changes))
                    spawn.assert_not_called()

    def test_endless_output_overflow_stops_before_timeout(self):
        import time
        with tempfile.TemporaryDirectory() as tmp:
            start = time.monotonic()
            result = run_command(CommandRequest((sys.executable, '-B', '-c',
                        "import os\nwhile True: os.write(1,b'x'*8192)"), tmp,
                        timeout_seconds=10, max_stdout_bytes=128))
            self.assertTrue(result.overflowed)
            self.assertTrue(result.killed)
            self.assertFalse(result.timed_out)
            self.assertLess(time.monotonic() - start, 3)
            self.assertEqual(result.stdout, '')

    def test_ignoring_sigterm_descendant_dies_after_parent_exits(self):
        import time
        with tempfile.TemporaryDirectory() as tmp:
            marker = Path(tmp) / 'pid'
            child_code = "import os,signal,time; signal.signal(signal.SIGTERM,signal.SIG_IGN); open(" + repr(str(marker)) + ", 'w').write(str(os.getpid())); time.sleep(30)"
            parent_code = "import subprocess,sys,time; subprocess.Popen([sys.executable,'-B','-c'," + repr(child_code) + "]); time.sleep(30)"
            result = run_command(CommandRequest((sys.executable, '-B', '-c', parent_code), tmp,
                                                 timeout_seconds=0.3, kill_grace_seconds=0.1))
            self.assertTrue(result.timed_out)
            pid = int(marker.read_text())
            deadline = time.monotonic() + 2
            while True:
                try:
                    os.kill(pid, 0)
                except ProcessLookupError:
                    break
                if time.monotonic() > deadline:
                    self.fail('SIGTERM-resistant descendant survived group cleanup')
                time.sleep(0.02)


if __name__ == "__main__":
    unittest.main()
