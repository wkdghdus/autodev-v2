from __future__ import annotations

import json
import multiprocessing
import tempfile
import unittest
from pathlib import Path

from autodev.safety.locks import LockContention, LockKey, LockManager, SafeLockError, SharedJsonMap
from autodev.safety.storage import ExpectedHashMismatch, SafeStore


class SafeLockTests(unittest.TestCase):
    def test_lock_order_and_contention_are_enforced(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "state"
            manager = LockManager(root)
            installation = LockKey("installation", "install-a")
            account = LockKey("account", "acct-a")
            with manager.acquire(account):
                with self.assertRaises(SafeLockError):
                    manager.acquire(installation)
            with manager.acquire(installation):
                other = LockManager(root)
                with self.assertRaises(LockContention):
                    other.acquire(installation)

    def test_canonical_same_level_order_required_for_group_acquire(self):
        with tempfile.TemporaryDirectory() as tmp:
            manager = LockManager(Path(tmp) / "state")
            with self.assertRaises(SafeLockError):
                manager.acquire_many(
                    [
                        LockKey("repository", "repo-b"),
                        LockKey("repository", "repo-a"),
                    ]
                )

    def test_shared_map_update_sequence_preserves_other_entries_and_cas(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "state"
            store = SafeStore(root)
            manager = LockManager(root)
            shared = SharedJsonMap(store, manager)
            first = store.write_json_atomic("accounts.json", {"project-a": {"account": 1}})
            sequence: list[str] = []
            result = shared.update_key(
                "accounts.json",
                LockKey("account", "acct-b"),
                "project-b",
                {"account": 2},
                expected_hash=first.sha256,
                checkpoint=sequence.append,
            )
            self.assertEqual(sequence, ["lock", "read", "hash", "merge", "before_temp", "file_fsync",
                                        "before_replace", "after_replace", "parent_fsync", "release"])
            self.assertEqual(result.status, "written")
            self.assertEqual(
                store.read_json("accounts.json"),
                {
                    "project-a": {"account": 1},
                    "project-b": {"account": 2},
                },
            )
            with self.assertRaises(ExpectedHashMismatch):
                shared.update_key(
                    "accounts.json",
                    LockKey("account", "acct-c"),
                    "project-c",
                    {"account": 3},
                    expected_hash=first.sha256,
                )

    def test_multiprocess_shared_map_updates_do_not_lose_records(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "state"
            SafeStore(root).write_json_atomic("accounts.json", {})
            barrier = multiprocessing.Barrier(4)
            queue: multiprocessing.Queue[tuple[str, str]] = multiprocessing.Queue()
            processes = [
                multiprocessing.Process(
                    target=_write_project,
                    args=(root, f"project-{index}", barrier, queue),
                )
                for index in range(4)
            ]
            for process in processes:
                process.start()
            for process in processes:
                process.join(15)
            results = [queue.get(timeout=5) for _ in processes]
            self.assertTrue(all(status == "ok" for status, _ in results), results)
            self.assertEqual({process.exitcode for process in processes}, {0})
            data = SafeStore(root).read_json("accounts.json")
            self.assertEqual(
                data,
                {f"project-{index}": {"owner": f"project-{index}"} for index in range(4)},
            )


def _write_project(
    root: Path,
    project_id: str,
    barrier: multiprocessing.Barrier,
    queue: multiprocessing.Queue[tuple[str, str]],
) -> None:
    try:
        store = SafeStore(root)
        shared = SharedJsonMap(store, LockManager(root))
        barrier.wait(timeout=10)
        shared.update_key(
            "accounts.json",
            LockKey("account", "shared"),
            project_id,
            {"owner": project_id},
        )
    except Exception as exc:  # pragma: no cover - failure detail crosses process boundary.
        queue.put(("error", type(exc).__name__))
    else:
        queue.put(("ok", project_id))



class LockOwnershipTests(unittest.TestCase):
    def test_stale_pid_metadata_cannot_steal_live_kernel_lock(self):
        import os
        import subprocess
        import sys
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / 'state'
            held = LockManager(root).acquire(LockKey('installation', 'owner'))
            try:
                metadata = json.loads(held.path.read_bytes())
                metadata['pid'] = 99999999
                metadata['acquired_at'] = 1
                held.path.write_text(json.dumps(metadata))
                script = '''
import sys
from pathlib import Path
from autodev.safety.locks import LockManager, LockKey, LockContention
try:
    LockManager(Path(sys.argv[1])).acquire(LockKey('installation', 'owner'))
except LockContention:
    print('blocked')
else:
    raise AssertionError('stale metadata stole live lock')
'''
                child = subprocess.run([sys.executable, '-B', '-c', script, str(root)],
                                       env={'PYTHONPATH': str(Path(__file__).resolve().parents[1] / 'src')},
                                       capture_output=True, text=True, timeout=10)
                self.assertEqual(child.returncode, 0, child.stderr)
                self.assertEqual(child.stdout.strip(), 'blocked')
                inode = held.path.stat().st_ino
            finally:
                held.release()
            with LockManager(root).acquire(LockKey('installation', 'owner')) as next_owner:
                self.assertEqual(next_owner.path.stat().st_ino, inode)
                self.assertNotEqual(json.loads(next_owner.path.read_bytes())['generation'], metadata['generation'])

    def test_lock_record_corruption_does_not_leak_or_admit(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / 'state'
            with LockManager(root).acquire(LockKey('installation', 'owner')) as held:
                path = held.path
            path.write_text('{CANARY-secret-value')
            with self.assertRaises(SafeLockError) as failure:
                LockManager(root).acquire(LockKey('installation', 'owner'))
            self.assertNotIn('CANARY-secret-value', str(failure.exception))

    def test_same_level_nested_order_and_group_release(self):
        with tempfile.TemporaryDirectory() as tmp:
            manager = LockManager(Path(tmp))
            with manager.acquire(LockKey('account', 'b')):
                with self.assertRaises(SafeLockError):
                    manager.acquire(LockKey('account', 'a'))
            with manager.acquire_many([LockKey('installation', 'a'), LockKey('repository', 'a')]):
                pass
            with manager.acquire(LockKey('installation', 'a')):
                pass


if __name__ == "__main__":
    unittest.main()
