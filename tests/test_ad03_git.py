from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

from autodev.safety.git_read import (
    SAFE_GIT_ENV, git_bucket_postcheck, git_check_ignore, git_repository_state, git_status_porcelain,
    git_tracked_paths, managed_bucket_evidence,
)
from autodev.safety.runner import CommandRequest, run_command


class AD03GitTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.repo = self.root / 'repo'
        self.repo.mkdir()
        self.env = {**SAFE_GIT_ENV, 'GIT_AUTHOR_NAME': 'Fixture',
                    'GIT_AUTHOR_EMAIL': 'fixture@example.invalid', 'GIT_COMMITTER_NAME': 'Fixture',
                    'GIT_COMMITTER_EMAIL': 'fixture@example.invalid'}

    def git(self, *args):
        result = subprocess.run(['/usr/bin/git', '-C', str(self.repo), *args], env=self.env,
                                capture_output=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        return result.stdout

    def initialize(self, commit=True):
        self.git('init', '-q')
        if commit:
            (self.repo / 'source.txt').write_text('source\n')
            self.git('add', 'source.txt')
            self.git('commit', '-qm', 'fixture')

    def test_non_git_unborn_attached_detached_and_dirty(self):
        state = git_repository_state(self.repo)
        self.assertTrue(state.ok, state)
        self.assertEqual(state.state, 'non_git')
        self.initialize(commit=False)
        state = git_repository_state(self.repo)
        self.assertTrue(state.ok, state)
        self.assertEqual(state.state, 'unborn')
        self.assertIsNone(state.revision)
        (self.repo / 'source.txt').write_text('source\n')
        self.git('add', 'source.txt')
        self.git('commit', '-qm', 'fixture')
        state = git_repository_state(self.repo)
        self.assertEqual(state.state, 'attached')
        self.assertFalse(state.dirty)
        self.assertEqual(len(state.revision), 40)
        self.assertTrue(state.config_sha256)
        self.assertTrue(state.index_sha256)
        self.git('checkout', '-q', '--detach')
        (self.repo / 'source.txt').write_text('changed\n')
        detached = git_repository_state(self.repo)
        self.assertTrue(detached.ok, detached)
        self.assertEqual(detached.state, 'detached')
        self.assertTrue(detached.dirty)
        self.assertNotEqual(detached.status_sha256, state.status_sha256)

    def test_bare_linked_and_corrupt_head_are_rejected(self):
        self.git('init', '-q', '--bare')
        self.assertEqual(git_repository_state(self.repo).reason, 'bare_repository_unsupported')
        linked = self.root / 'linked'
        linked.mkdir()
        (linked / '.git').write_text('gitdir: ../repo\n')
        self.assertEqual(git_repository_state(linked).reason, 'linked_git_dir_unsupported')
        ordinary = self.root / 'ordinary'
        ordinary.mkdir()
        self.repo = ordinary
        self.initialize()
        branch = git_repository_state(self.repo).branch
        (self.repo / '.git' / branch).write_text('a' * 40 + '\n')
        corrupt = git_repository_state(self.repo)
        self.assertFalse(corrupt.ok, corrupt)
        self.assertNotEqual(corrupt.state, 'unborn')

    def test_index_tracks_staged_and_deleted_and_keeps_literal_bucket(self):
        self.initialize()
        bucket = self.repo / '.trees'
        bucket.mkdir()
        tracked = bucket / 'tracked.txt'
        tracked.write_text('tracked\n')
        self.git('add', '.trees/tracked.txt')
        self.git('commit', '-qm', 'tracked bucket')
        tracked.unlink()
        staged = bucket / 'staged ü.txt'
        staged.write_text('staged\n')
        self.git('add', '.trees/staged ü.txt')
        index = self.repo / '.git/index'
        before = (index.read_bytes(), index.stat().st_mtime_ns)
        evidence = managed_bucket_evidence(self.repo, '.trees')
        self.assertFalse(evidence.ok)
        self.assertEqual(evidence.reason, 'tracked_bucket_paths')
        self.assertEqual(evidence.tracked_paths, ('.trees/staged ü.txt', '.trees/tracked.txt'))
        self.assertEqual(before, (index.read_bytes(), index.stat().st_mtime_ns))
        self.assertFalse(git_bucket_postcheck(self.repo, '.trees'))
        self.assertEqual(git_tracked_paths(self.repo, '.trees-other').paths, ())

    def test_staged_private_state_is_visible_to_transaction_preflight(self):
        self.initialize()
        state = self.repo / '.agent/.init-state'
        state.mkdir(parents=True)
        (state / 'owner.json').write_text('{}')
        self.git('add', '.agent/.init-state/owner.json')
        evidence = git_tracked_paths(self.repo, '.agent/.init-state')
        self.assertTrue(evidence.ok)
        self.assertEqual(evidence.paths, ('.agent/.init-state/owner.json',))

    def test_negative_ignore_is_complete_observation_not_unknown(self):
        self.initialize()
        observation = git_check_ignore(self.repo, ('.trees',))
        self.assertTrue(observation.ok, observation)
        self.assertFalse(observation.observations[0].ignored)
        self.assertEqual(observation.observations[0].source, '')
        (self.repo / '.trees').mkdir()
        (self.repo / '.gitignore').write_text('.trees/\n!.trees/\n')
        observation = git_check_ignore(self.repo, ('.trees',))
        self.assertTrue(observation.ok, observation)
        self.assertFalse(observation.observations[0].ignored)
        self.assertEqual(observation.observations[0].pattern, '!.trees/')
        self.assertEqual(observation.observations[0].line, 2)

    def test_append_preserves_crlf_prefix_and_directory_proof_overrides_negations(self):
        self.initialize()
        bucket = self.repo / '.trees'
        (bucket / 'nested').mkdir(parents=True)
        (bucket / 'nested/file.txt').write_text('file')
        (bucket / 'nested/.gitignore').write_text('!file.txt\n')
        original = b'# user comment\r\n.trees/*\r\n!.trees/nested/'
        ignore = self.repo / '.gitignore'
        ignore.write_bytes(original)
        evidence = managed_bucket_evidence(self.repo, '.trees')
        self.assertTrue(evidence.ok, evidence)
        self.assertEqual(evidence.ignore_original, original)
        self.assertEqual(evidence.ignore_proposed, original + b'\r\n/.trees/\r\n')
        self.assertIn('.trees/', evidence.probes)
        self.assertIn('.trees/nested/file.txt', evidence.probes)
        ignore.write_bytes(evidence.ignore_proposed)
        self.assertTrue(git_bucket_postcheck(self.repo, '.trees'))
        evidence = managed_bucket_evidence(self.repo, '.trees')
        self.assertEqual(evidence.reason, 'already_ignored')
        self.assertIsNone(evidence.ignore_proposed)
        self.assertTrue(all(item.ignored and item.source == '.gitignore' for item in evidence.observations))

    def test_only_ignored_sentinel_cannot_prove_directory_exclusion(self):
        self.initialize()
        (self.repo / '.gitignore').write_text('.trees/sentinel\n')
        bucket = self.repo / '.trees'
        bucket.mkdir()
        (bucket / 'sentinel').write_text('x')
        evidence = managed_bucket_evidence(self.repo, '.trees')
        self.assertTrue(evidence.ok)
        self.assertEqual(evidence.reason, 'ignore_append_required')
        self.assertEqual(evidence.ignore_proposed, b'.trees/sentinel\n/.trees/\n')

    def test_host_excludes_disabled_info_exclude_provenance_retained(self):
        self.initialize()
        global_ignore = self.root / 'host.ignore'
        global_ignore.write_text('.trees/\n')
        self.git('config', 'core.excludesFile', str(global_ignore))
        evidence = managed_bucket_evidence(self.repo, '.trees')
        self.assertEqual(evidence.reason, 'ignore_append_required')
        (self.repo / '.git/info/exclude').write_text('.trees/\n')
        evidence = managed_bucket_evidence(self.repo, '.trees')
        self.assertEqual(evidence.reason, 'already_ignored')
        self.assertEqual(evidence.observations[0].source, '.git/info/exclude')

    def test_ignore_source_bytes_bind_even_when_matching_observations_stay_equal(self):
        self.initialize()
        ignore = self.repo / '.gitignore'
        ignore.write_text('/.trees/\n# original\n')
        before = managed_bucket_evidence(self.repo, '.trees')
        ignore.write_text('/.trees/\n# revised\n')
        after = managed_bucket_evidence(self.repo, '.trees')
        self.assertEqual(before.reason, 'already_ignored')
        self.assertEqual(before.observations, after.observations)
        self.assertNotEqual(before.ignore_source_hashes, after.ignore_source_hashes)

    def test_metadata_symlink_and_indirect_branch_fail_before_head_reads(self):
        self.initialize()
        head = self.repo / '.git/HEAD'
        original = head.read_bytes()
        head.unlink()
        outside = self.root / 'outside-head'
        outside.write_bytes(original)
        head.symlink_to(outside)
        self.assertFalse(git_repository_state(self.repo).ok)
        head.unlink()
        head.write_bytes(original)
        branch = original[5:].decode().strip()
        (self.repo / '.git' / branch).write_text('ref: refs/heads/other\n')
        self.assertFalse(git_repository_state(self.repo).ok)
        head.write_text('ref: refs/heads/bad.lock\n')
        self.assertFalse(git_repository_state(self.repo).ok)

    def test_ignore_reads_share_callback_budget_and_aggregate_limit_precedes_open(self):
        self.initialize()
        bucket = self.repo / '.trees'
        bucket.mkdir()
        for number in range(33):
            directory = bucket / str(number)
            directory.mkdir()
            (directory / '.gitignore').write_bytes(b'#' * 131072)
        calls = []
        total = 0
        def read(relative):
            nonlocal total
            calls.append(relative)
            path = self.repo / relative
            content = path.read_bytes() if path.exists() else None
            total += len(content or b'')
            return content
        evidence = managed_bucket_evidence(self.repo, '.trees', read_bytes=read)
        self.assertFalse(evidence.ok)
        self.assertEqual(len(calls), len(set(calls)))
        self.assertLessEqual(total, 4194304)
        self.assertFalse(managed_bucket_evidence(self.repo, '.trees').ok)

    def test_git_pack_enumeration_has_finite_absence_bound(self):
        self.initialize()
        pack = self.repo / '.git/objects/pack'
        for number in range(2001):
            (pack / str(number)).touch()
        self.assertEqual(git_status_porcelain(self.repo).reason, 'git_metadata_limit')

    def test_literal_unicode_spaces_and_no_newline_preservation(self):
        self.initialize()
        (self.repo / '.gitignore').write_bytes(b'# intact')
        evidence = managed_bucket_evidence(self.repo, '.trees/with spaces ü')
        self.assertTrue(evidence.ok, evidence)
        self.assertEqual(evidence.ignore_proposed, '# intact\n/.trees/with spaces ü/\n'.encode())
        (self.repo / '.gitignore').write_bytes(evidence.ignore_proposed)
        self.assertTrue(git_bucket_postcheck(self.repo, '.trees/with spaces ü'))

    def test_invalid_bucket_arguments_never_start_git(self):
        for bucket in ('../escape', '/absolute', '-option', '.trees/*', '.trees/[x]', '.trees/!x',
                       '.trees\n', '.trees\x00', 'docs/trees', '.agent/trees', '.git/trees',
                       '.trees/$(touch x)', '.trees//child', '.trees/child '):
            with self.subTest(bucket=bucket):
                def fail(request):
                    self.fail('invalid bucket started Git')
                self.assertFalse(managed_bucket_evidence(self.repo, bucket, runner=fail).ok)
        self.assertEqual(managed_bucket_evidence(self.repo, None).strategy, 'unknown')

    def test_special_symlink_hardlink_and_unsupported_ignore_encoding_fail_closed(self):
        self.initialize()
        ignore = self.repo / '.gitignore'
        os.mkfifo(ignore)
        self.assertFalse(managed_bucket_evidence(self.repo, '.trees').ok)
        ignore.unlink()
        ignore.symlink_to(self.root / 'outside')
        self.assertFalse(managed_bucket_evidence(self.repo, '.trees').ok)
        ignore.unlink()
        ignore.write_bytes(b'\xff')
        self.assertFalse(managed_bucket_evidence(self.repo, '.trees').ok)
        ignore.write_bytes(b'')
        os.link(ignore, self.root / 'linked-ignore')
        self.assertFalse(managed_bucket_evidence(self.repo, '.trees').ok)

    def test_git_overflow_and_fatal_ignore_results_are_unknown(self):
        self.initialize()
        for mode in ('truncated', 'fatal'):
            def runner(request):
                result = run_command(request)
                if 'check-ignore' in request.argv:
                    return replace(result, stdout_truncated=mode == 'truncated',
                                   returncode=128 if mode == 'fatal' else result.returncode)
                return result
            result = git_check_ignore(self.repo, ('.trees/',), runner=runner)
            self.assertFalse(result.ok)
            self.assertEqual(result.reason, 'git_ignore_unknown')

    def test_bucket_limit_and_symlink_descendants_block_proof(self):
        self.initialize()
        bucket = self.repo / '.trees'
        bucket.mkdir()
        (bucket / 'linked').symlink_to(self.root)
        self.assertFalse(managed_bucket_evidence(self.repo, '.trees').ok)
        (bucket / 'linked').unlink()
        for number in range(2001):
            (bucket / str(number)).touch()
        self.assertFalse(managed_bucket_evidence(self.repo, '.trees').ok)


class AD03BoundedStdinTests(unittest.TestCase):
    def test_binary_stdin_full_duplex_and_early_exit(self):
        with tempfile.TemporaryDirectory() as tmp:
            data = b'a\x00b' * 20000
            script = 'import sys; sys.stdout.buffer.write(b"x"*60000); sys.stdout.flush(); data=sys.stdin.buffer.read(); sys.stdout.buffer.write(data)'
            result = run_command(CommandRequest((sys.executable, '-B', '-c', script), tmp,
                                 stdin_bytes=data, max_stdout_bytes=130000))
            self.assertEqual(result.returncode, 0)
            self.assertEqual(result.stdout.encode(), b'x' * 60000 + data)
            early = run_command(CommandRequest((sys.executable, '-B', '-c', 'pass'), tmp,
                                stdin_bytes=b'x' * 65536))
            self.assertEqual(early.returncode, 0)

    def test_stuck_stdin_times_out_and_invalid_input_never_spawns(self):
        with tempfile.TemporaryDirectory() as tmp:
            request = CommandRequest((sys.executable, '-B', '-c', 'import time; time.sleep(30)'),
                                     tmp, stdin_bytes=b'x' * 65536, timeout_seconds=0.1)
            result = run_command(request)
            self.assertTrue(result.timed_out)
            self.assertTrue(result.killed)
            for invalid in (b'x' * 65537, 'text'):
                with patch('subprocess.Popen') as spawn, self.assertRaises(ValueError):
                    run_command(replace(request, stdin_bytes=invalid))
                spawn.assert_not_called()


if __name__ == '__main__':
    unittest.main()
