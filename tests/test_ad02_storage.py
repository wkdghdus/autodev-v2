from __future__ import annotations

import os
import signal
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path

from autodev.safety.storage import ExpectedHashMismatch, SafeStorageError, SafeStore


class SafeStorageTests(unittest.TestCase):
    def test_expected_hash_mismatch_rejects_without_overwrite(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = SafeStore(Path(tmp) / "state")
            first = store.write_json_atomic("registry.json", {"project-a": 1})
            with self.assertRaises(ExpectedHashMismatch):
                store.write_json_atomic(
                    "registry.json",
                    {"project-b": 2},
                    expected_hash="stale-preview",
                )
            self.assertEqual(store.current_hash("registry.json"), first.sha256)
            self.assertEqual(store.read_json("registry.json"), {"project-a": 1})

    def test_safe_root_rejects_traversal_symlink_and_permissive_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "state"
            store = SafeStore(root)
            with self.assertRaises(SafeStorageError):
                store.write_json_atomic("../escape.json", {"bad": True})
            outside = Path(tmp) / "outside.json"
            outside.write_text("{}\n", encoding="utf-8")
            (root / "linked.json").symlink_to(outside)
            with self.assertRaises(SafeStorageError):
                store.read_json("linked.json")
            store.write_json_atomic("too-open.json", {"ok": True})
            os.chmod(root / "too-open.json", 0o666)
            with self.assertRaises(SafeStorageError):
                store.read_json("too-open.json")

    def test_atomic_failure_checkpoints_leave_parseable_visible_state(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = SafeStore(Path(tmp) / "state")
            old = store.write_json_atomic("record.json", {"version": "old"})

            def fail_before_replace(label: str, _path: Path) -> None:
                if label == "before_replace":
                    raise RuntimeError("injected")

            with self.assertRaises(RuntimeError):
                store.write_json_atomic("record.json", {"version": "new"}, checkpoint=fail_before_replace)
            self.assertEqual(store.recover("record.json").value, {"version": "old"})
            self.assertEqual(store.current_hash("record.json"), old.sha256)
            self.assertEqual(store.recover("record.json").status, "write_uncertain")
            with self.assertRaises(SafeStorageError):
                store.write_json_atomic("record.json", {"version": "blocked"})
            self.assertTrue(store.reconcile_write("record.json").admissible)

            result = store.write_json_atomic(
                "record.json",
                {"version": "new"},
                expected_hash=old.sha256,
                fail_at="parent_fsync",
            )
            self.assertEqual(result.parent_fsync, "uncertain")
            recovered = store.recover("record.json")
            self.assertEqual(recovered.status, "write_uncertain")
            self.assertFalse(recovered.admissible)
            self.assertEqual(recovered.value, {"version": "new"})

    def test_corrupt_record_recovers_as_untrusted(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "state"
            store = SafeStore(root)
            path = root / "record.json"
            path.write_text("{not json", encoding="utf-8")
            os.chmod(path, 0o600)
            recovered = store.recover("record.json")
            self.assertEqual(recovered.status, "corrupt_untrusted")
            self.assertIsNone(recovered.value)

    def test_real_sigkill_before_and_after_replace_leave_parseable_record(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "state"
            store = SafeStore(root)
            store.write_json_atomic("record.json", {"version": "old"})
            before_code = self._kill_script("before_replace")
            before = subprocess.run(
                [sys.executable, "-B", "-c", before_code, str(root)],
                env={"PYTHONPATH": str(Path(__file__).resolve().parents[1] / "src")},
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=False,
            )
            self.assertEqual(before.returncode, -signal.SIGKILL)
            self.assertIn(store.read_json("record.json")["version"], {"old", "new"})
            self.assertEqual(store.recover("record.json").status, "write_uncertain")
            store.reconcile_write("record.json")

            after_code = self._kill_script("after_replace")
            after = subprocess.run(
                [sys.executable, "-B", "-c", after_code, str(root)],
                env={"PYTHONPATH": str(Path(__file__).resolve().parents[1] / "src")},
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=False,
            )
            self.assertEqual(after.returncode, -signal.SIGKILL)
            self.assertEqual(store.recover("record.json").status, "write_uncertain")
            self.assertIn(store.read_json("record.json")["version"], {"old", "new"})

    def _kill_script(self, checkpoint: str) -> str:
        return textwrap.dedent(
            f"""
            import os
            import signal
            import sys
            from pathlib import Path
            from autodev.safety.storage import SafeStore

            store = SafeStore(Path(sys.argv[1]))

            def kill(label, path):
                if label == {checkpoint!r}:
                    os.kill(os.getpid(), signal.SIGKILL)

            store.write_json_atomic("record.json", {{"version": "new"}}, checkpoint=kill)
            """
        )




class StorageBoundaryTests(unittest.TestCase):
    def test_parent_symlink_refused_before_outside_directory_creation(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / 'state'
            outside = Path(tmp) / 'outside'
            outside.mkdir(mode=0o700)
            store = SafeStore(root)
            (root / 'link').symlink_to(outside)
            with self.assertRaises(SafeStorageError):
                store.write_json_atomic('link/new/file.json', {})
            self.assertFalse((outside / 'new').exists())
            with self.assertRaises(SafeStorageError):
                SafeStore(root / 'link')

    def test_unsafe_root_is_rejected_without_chmod_repair(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / 'state'
            root.mkdir(mode=0o777)
            root.chmod(0o777)
            with self.assertRaises(SafeStorageError):
                SafeStore(root)
            self.assertEqual(root.stat().st_mode & 0o777, 0o777)

    def test_corrupt_recovery_metadata_blocks_overwrite(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = SafeStore(Path(tmp))
            store.write_json_atomic('nested/file.json', {'old': 1})
            store._recovery_path('nested/file.json').write_text('{')
            self.assertEqual(store.recover('nested/file.json').status, 'corrupt_untrusted')
            with self.assertRaises(SafeStorageError):
                store.write_json_atomic('nested/file.json', {'new': 2})
            self.assertEqual(store.read_json('nested/file.json'), {'old': 1})

    def test_permissions_and_expected_absence(self):
        from autodev.safety.storage import ABSENT
        with tempfile.TemporaryDirectory() as tmp:
            store = SafeStore(Path(tmp) / 'state')
            store.write_json_atomic('nested/file.json', {}, expected_hash=ABSENT)
            self.assertEqual(store.root.stat().st_mode & 0o777, 0o700)
            self.assertEqual(store.resolve('nested/file.json').stat().st_mode & 0o777, 0o600)
            self.assertEqual(store.resolve('nested/file.json').parent.stat().st_mode & 0o777, 0o700)
            with self.assertRaises(ExpectedHashMismatch):
                store.write_json_atomic('nested/file.json', {'changed': 1}, expected_hash=ABSENT)

    def test_disk_full_before_temp_and_file_sync_preserves_old(self):
        import errno
        for stage in ('before_temp', 'file_fsync', 'after_replace'):
            with self.subTest(stage=stage), tempfile.TemporaryDirectory() as tmp:
                store = SafeStore(Path(tmp))
                store.write_json_atomic('file.json', {'version': 'old'})
                def failure(label, path):
                    if label == stage:
                        raise OSError(errno.ENOSPC, 'fixture disk full')
                with self.assertRaises(OSError):
                    store.write_json_atomic('file.json', {'version': 'new'}, checkpoint=failure)
                self.assertIn(store.read_json('file.json')['version'], {'old', 'new'})
                self.assertFalse(store.recover('file.json').admissible)


if __name__ == "__main__":
    unittest.main()
