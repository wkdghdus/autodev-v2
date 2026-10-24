from __future__ import annotations

import json
import os
import stat
import tempfile
import unittest
from dataclasses import dataclass
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from autodev.init.apply import (STATE, apply_proposal, inspect_recovery, recover_repository)
from autodev.safety.repository_files import (FileSnapshot, checked_root, publish, snapshot, stage)
from autodev.safety.types import SafetyError


class Crash(BaseException):
    pass


@dataclass(frozen=True)
class Operation:
    path: str
    original: bytes | None
    proposed: bytes
    mode: int = 0o644


class RepositoryWriteTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name).resolve()

    def proposal(self, *operations):
        return SimpleNamespace(root=self.root, status='ready', digest='a' * 64,
                               operations=operations, options={})

    def apply(self, proposal, **kwargs):
        return apply_proposal(proposal, recompute=lambda: proposal, **kwargs)

    def interrupt(self, proposal, label):
        def checkpoint(observed, _path):
            if label == observed:
                raise Crash()
        with self.assertRaises(Crash):
            self.apply(proposal, checkpoint=checkpoint)

    def test_preview_inspection_and_noop_create_nothing(self):
        self.assertEqual(inspect_recovery(self.root)['status'], 'clean')
        self.assertEqual(self.apply(self.proposal()).status, 'noop')
        self.assertEqual(list(self.root.iterdir()), [])

    def test_apply_exact_bytes_and_mode(self):
        old = b'# comment\r\n/old/\r\nlast'
        path = self.root / '.gitignore'
        path.write_bytes(old)
        path.chmod(0o640)
        proposal = self.proposal(Operation('.gitignore', old, old + b'\r\n/bucket/\r\n'))
        with patch('autodev.safety.git_read.git_bucket_postcheck', return_value=True, create=True):
            proposal.options['worktree_bucket'] = 'bucket'
            result = self.apply(proposal)
        self.assertEqual(result.status, 'applied', result)
        self.assertEqual(path.read_bytes(), proposal.operations[0].proposed)
        self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o640)
        self.assertEqual(inspect_recovery(self.root)['status'], 'clean')

    def test_new_parents_and_deterministic_publication_order(self):
        seen = []
        result = self.apply(self.proposal(Operation('new/b.yaml', None, b'b'), Operation('new/a.yaml', None, b'a')),
                            checkpoint=lambda label, path: seen.append(path) if label == 'after_publish' else None)
        self.assertEqual(result.status, 'applied')
        self.assertEqual(seen, ['new/a.yaml', 'new/b.yaml'])
        record = json.loads((self.root / STATE / 'transaction.json').read_text())
        self.assertEqual(record['phase'], 'committed')
        self.assertEqual(len(record['parents']), 1)

    def test_absent_publish_cannot_clobber_racing_creation(self):
        temporary, _identity = stage(self.root, 'new.yaml', b'ours', 0o644)
        expected = snapshot(self.root, 'new.yaml')
        real_link = os.link
        def racing_link(*args, **kwargs):
            (self.root / 'new.yaml').write_bytes(b'user')
            return real_link(*args, **kwargs)
        with patch('autodev.safety.repository_files.os.link', side_effect=racing_link):
            with self.assertRaises(FileExistsError):
                publish(self.root, 'new.yaml', temporary, expected, staged=FileSnapshot(b'ours', 0o644, _identity))
        self.assertEqual((self.root / 'new.yaml').read_bytes(), b'user')

    def test_existing_target_inode_change_refuses_publish(self):
        target = self.root / 'file'
        target.write_bytes(b'old')
        before = snapshot(self.root, 'file')
        temporary, identity = stage(self.root, 'file', b'new', 0o644)
        other = self.root / 'other'
        other.write_bytes(b'old')
        other.replace(target)
        with self.assertRaises(SafetyError):
            publish(self.root, 'file', temporary, before, staged=FileSnapshot(b'new', 0o644, identity))
        self.assertEqual(target.read_bytes(), b'old')

    def test_stale_digest_is_pure(self):
        result = self.apply(self.proposal(Operation('file', None, b'new')), expected_digest='b' * 64)
        self.assertEqual(result.status, 'stale_proposal')
        self.assertEqual(list(self.root.iterdir()), [])

    def test_prebootstrap_recompute_stale_is_pure(self):
        proposal = self.proposal(Operation('file', None, b'new'))
        changed = self.proposal()
        changed.digest = 'b' * 64
        result = apply_proposal(proposal, recompute=lambda: changed)
        self.assertEqual(result.status, 'stale_proposal')
        self.assertEqual(list(self.root.iterdir()), [])

    def test_late_stale_discloses_only_infrastructure(self):
        proposal = self.proposal(Operation('file', None, b'new'))
        calls = []
        def recompute():
            calls.append(None)
            changed = self.proposal()
            return proposal if len(calls) == 1 else changed
        def checkpoint(label, _path):
            if label == 'lock_acquired':
                proposal.digest = 'b' * 64
        result = apply_proposal(proposal, recompute=recompute, checkpoint=checkpoint)
        self.assertEqual(result.status, 'stale_proposal')
        self.assertEqual(result.alignment_changes, ())
        self.assertTrue(result.infrastructure_effects)
        self.assertFalse((self.root / 'file').exists())

    def test_exception_rolls_back_existing_bytes_modes_and_new_files(self):
        (self.root / 'a').write_bytes(b'original\r\n# keep')
        (self.root / 'a').chmod(0o640)
        def failure(label, _path):
            if label == 'before_commit':
                raise OSError('injected')
        result = self.apply(self.proposal(Operation('a', b'original\r\n# keep', b'new'),
                                          Operation('new/b', None, b'new')), checkpoint=failure)
        self.assertEqual(result.status, 'failed')
        self.assertEqual((self.root / 'a').read_bytes(), b'original\r\n# keep')
        self.assertEqual(stat.S_IMODE((self.root / 'a').stat().st_mode), 0o640)
        self.assertFalse((self.root / 'new').exists())
        self.assertEqual(inspect_recovery(self.root)['status'], 'clean')

    def test_identical_bytes_external_inode_survives_rollback(self):
        def failure(label, path):
            if label == 'after_publish':
                replacement = self.root / 'user'
                replacement.write_bytes(b'new')
                replacement.replace(self.root / path)
                raise OSError('injected')
        result = self.apply(self.proposal(Operation('file', None, b'new')), checkpoint=failure)
        self.assertEqual(result.status, 'recovery_required')
        self.assertEqual((self.root / 'file').read_bytes(), b'new')
        self.assertEqual(recover_repository(self.root).status, 'recovery_required')

    def test_pending_preview_is_pure_and_explicit_recovery_restores(self):
        for boundary in ('after_intent', 'before_publish', 'after_publish', 'after_checkpoint', 'before_commit'):
            with self.subTest(boundary=boundary), tempfile.TemporaryDirectory() as directory:
                self.root = Path(directory).resolve()
                (self.root / 'a').write_bytes(b'old')
                proposal = self.proposal(Operation('a', b'old', b'new'), Operation('b', None, b'new'))
                self.interrupt(proposal, boundary)
                before = {p.relative_to(self.root): (p.read_bytes(), p.stat().st_mtime_ns)
                          for p in self.root.rglob('*') if p.is_file()}
                self.assertEqual(inspect_recovery(self.root)['status'], 'recovery_required')
                after = {p.relative_to(self.root): (p.read_bytes(), p.stat().st_mtime_ns)
                         for p in self.root.rglob('*') if p.is_file()}
                self.assertEqual(before, after)
                self.assertEqual(self.apply(proposal).status, 'recovery_required')
                self.assertEqual(recover_repository(self.root).status, 'recovered')
                self.assertEqual((self.root / 'a').read_bytes(), b'old')
                self.assertFalse((self.root / 'b').exists())

    def test_originals_all_durable_before_first_publish(self):
        (self.root / 'a').write_bytes(b'a')
        (self.root / 'b').write_bytes(b'b')
        self.interrupt(self.proposal(Operation('a', b'a', b'new'), Operation('b', b'b', b'new')), 'before_publish')
        record = json.loads((self.root / STATE / 'transaction.json').read_text())
        self.assertEqual([item['original'] for item in record['operations']], ['YQ==', 'Yg=='])
        self.assertIsNotNone(record['operations'][0]['published_inode'])
        self.assertEqual((self.root / 'a').read_bytes(), b'a')

    def test_bootstrap_crash_is_never_adopted(self):
        self.interrupt(self.proposal(Operation('file', None, b'new')), 'bootstrap_directory')
        self.assertEqual(inspect_recovery(self.root)['status'], 'bootstrap_recovery_required')
        self.assertEqual(self.apply(self.proposal(Operation('file', None, b'new'))).status, 'bootstrap_recovery_required')
        self.assertFalse((self.root / 'file').exists())

    def test_foreign_owner_refused_without_changes(self):
        state = self.root / STATE
        state.mkdir(parents=True, mode=0o700)
        (state / 'owner.json').write_text('{}')
        (state / 'owner.json').chmod(0o600)
        result = self.apply(self.proposal(Operation('file', None, b'new')))
        self.assertEqual(result.status, 'bootstrap_recovery_required')
        self.assertEqual((state / 'owner.json').read_text(), '{}')

    def test_same_root_lock_identity_survives_transactions_and_recovery(self):
        self.assertEqual(self.apply(self.proposal(Operation('first', None, b'new'))).status, 'applied')
        locks = list((self.root / STATE / 'locks/repository').glob('*.lock'))
        self.assertEqual(len(locks), 1)
        identity = locks[0].stat().st_ino
        self.interrupt(self.proposal(Operation('second', None, b'new')), 'after_publish')
        self.assertEqual(recover_repository(self.root).status, 'recovered')
        self.assertEqual(locks[0].stat().st_ino, identity)
        self.assertEqual(len(list(locks[0].parent.iterdir())), 1)

    def test_links_special_targets_and_escapes_refused(self):
        (self.root / 'source').write_bytes(b'old')
        os.link(self.root / 'source', self.root / 'hard')
        (self.root / 'linked').symlink_to(self.root / 'source')
        os.mkfifo(self.root / 'fifo')
        for path in ('hard', 'linked', 'fifo', '../escape', '/absolute'):
            with self.subTest(path=path):
                result = self.apply(self.proposal(Operation(path, None, b'new')))
                self.assertNotEqual(result.status, 'applied')
        self.assertEqual((self.root / 'source').read_bytes(), b'old')

    def test_linked_root_and_parent_rejected(self):
        alias = self.root / 'alias'
        alias.symlink_to(self.root, target_is_directory=True)
        with self.assertRaises(SafetyError):
            checked_root(alias)
        (self.root / 'dir').symlink_to(self.root, target_is_directory=True)
        result = self.apply(self.proposal(Operation('dir/file', None, b'new')))
        self.assertNotEqual(result.status, 'applied')

    def test_unchanged_noop_does_not_touch_existing_state(self):
        self.apply(self.proposal(Operation('file', None, b'new')))
        before = {p: p.stat().st_mtime_ns for p in self.root.rglob('*')}
        self.assertEqual(self.apply(self.proposal()).status, 'noop')
        self.assertEqual(before, {p: p.stat().st_mtime_ns for p in self.root.rglob('*')})

    def test_unrecorded_staging_inode_requires_manual_reconciliation(self):
        from autodev.init import apply as implementation
        original = implementation.stage
        def die_after_staging(*args, **kwargs):
            original(*args, **kwargs)
            raise Crash()
        with patch.object(implementation, 'stage', side_effect=die_after_staging):
            with self.assertRaises(Crash):
                self.apply(self.proposal(Operation('file', None, b'new')))
        self.assertEqual(recover_repository(self.root).status, 'recovery_required')
        self.assertTrue(list(self.root.glob('.autodev-init-*')))
        self.assertEqual(inspect_recovery(self.root)['status'], 'recovery_required')

    def test_unrecorded_parent_inode_requires_manual_reconciliation(self):
        from autodev.init import apply as implementation
        original = implementation.create_parent
        def die_after_mkdir(*args, **kwargs):
            original(*args, **kwargs)
            raise Crash()
        with patch.object(implementation, 'create_parent', side_effect=die_after_mkdir):
            with self.assertRaises(Crash):
                self.apply(self.proposal(Operation('new/file', None, b'new')))
        self.assertEqual(recover_repository(self.root).status, 'recovery_required')
        self.assertTrue((self.root / 'new').is_dir())

    def test_each_parent_component_open_rejects_injected_symlink_swap(self):
        (self.root / 'a/b').mkdir(parents=True)
        outside = self.root / 'outside'
        (outside / 'b').mkdir(parents=True)
        real_open = os.open
        swapped = []
        def swap_before_component_open(path, *args, **kwargs):
            if path == 'a' and kwargs.get('dir_fd') is not None and not swapped:
                swapped.append(True)
                (self.root / 'a').rename(self.root / 'moved')
                (self.root / 'a').symlink_to(outside, target_is_directory=True)
            return real_open(path, *args, **kwargs)
        with patch('autodev.safety.repository_files.os.open', side_effect=swap_before_component_open):
            with self.assertRaises((OSError, SafetyError)):
                stage(self.root, 'a/b/file', b'new', 0o644)
        self.assertEqual(list((outside / 'b').iterdir()), [])

    def test_link_publication_interruption_reconciles_owned_staging_link(self):
        original_unlink = os.unlink
        def die_before_staging_unlink(path, *args, **kwargs):
            if str(path).startswith('.autodev-init-') and kwargs.get('dir_fd') is not None:
                raise Crash()
            return original_unlink(path, *args, **kwargs)
        with patch('autodev.safety.repository_files.os.unlink', side_effect=die_before_staging_unlink) as mocked:
            with patch.object(os, 'supports_dir_fd', os.supports_dir_fd | {mocked}):
                with self.assertRaises(Crash):
                    self.apply(self.proposal(Operation('file', None, b'new')))
        self.assertEqual((self.root / 'file').stat().st_nlink, 2)
        self.assertEqual(recover_repository(self.root).status, 'recovered')
        self.assertFalse((self.root / 'file').exists())
        self.assertEqual(list(self.root.glob('.autodev-init-*')), [])

    def test_altered_staging_bytes_never_publish_and_survive_recovery(self):
        published = []
        def tamper(label, path):
            if label == 'before_publish':
                record = json.loads((self.root / STATE / 'transaction.json').read_text())
                staging = next(item['staging'] for item in record['operations'] if item['path'] == path)
                (self.root / staging).write_bytes(b'user edit')
            if label == 'after_publish':
                published.append(path)
        result = self.apply(self.proposal(Operation('file', None, b'new')), checkpoint=tamper)
        self.assertEqual(result.status, 'recovery_required')
        self.assertFalse((self.root / 'file').exists())
        self.assertEqual(published, [])
        temporary = next(self.root.glob('.autodev-init-*'))
        self.assertEqual(temporary.read_bytes(), b'user edit')
        self.assertEqual(recover_repository(self.root).status, 'recovery_required')
        self.assertEqual(temporary.read_bytes(), b'user edit')

    def test_bootstrap_parent_swap_writes_only_pinned_repository_directory(self):
        outside = self.root / 'outside'
        outside.mkdir()
        original = os.mkdir
        swapped = []
        def swap_at_private_mkdir(path, *args, **kwargs):
            if path == '.init-state' and kwargs.get('dir_fd') is not None and not swapped:
                swapped.append(True)
                (self.root / '.agent').rename(self.root / 'original-agent')
                (self.root / '.agent').symlink_to(outside, target_is_directory=True)
            return original(path, *args, **kwargs)
        with patch('autodev.init.apply.os.mkdir', side_effect=swap_at_private_mkdir):
            result = self.apply(self.proposal(Operation('file', None, b'new')))
        self.assertNotEqual(result.status, 'applied')
        self.assertEqual(list(outside.iterdir()), [])
        self.assertFalse((self.root / 'file').exists())


if __name__ == '__main__':
    unittest.main()
