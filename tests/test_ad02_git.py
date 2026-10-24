from __future__ import annotations

import os
import subprocess
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

from autodev.safety.git_read import SAFE_GIT_ENV, git_show_file, git_status_porcelain, parse_git_version
from autodev.safety.runner import CommandResult, run_command


def result(request, stdout='', returncode=0):
    return CommandResult(tuple(request.argv), str(request.cwd), returncode, stdout, '',
                         len(stdout.encode()), 0, False, False, False, False, False, ())


class PassiveGitTests(unittest.TestCase):
    def setup_repo(self, root):
        repo = root / 'repo'
        repo.mkdir()
        env = {**SAFE_GIT_ENV, 'GIT_AUTHOR_NAME': 'Fixture', 'GIT_AUTHOR_EMAIL': 'fixture@example.invalid',
               'GIT_COMMITTER_NAME': 'Fixture', 'GIT_COMMITTER_EMAIL': 'fixture@example.invalid'}
        def git(*args):
            child = subprocess.run(['/usr/bin/git', '-C', str(repo), *args], env=env,
                                   capture_output=True, timeout=10)
            self.assertEqual(child.returncode, 0, child.stderr)
        git('init', '-q')
        (repo / 'file.txt').write_text('old\n')
        git('add', 'file.txt')
        git('commit', '-qm', 'fixture')
        return repo

    def test_version_gate_fails_before_repository_reads(self):
        with tempfile.TemporaryDirectory() as tmp:
            for version, reason in [('git version 2.35.9', 'git_version_too_old'), ('not git', 'git_version_unparseable')]:
                calls = []
                def runner(request):
                    calls.append(tuple(request.argv))
                    return result(request, version)
                self.assertEqual(git_status_porcelain(tmp, runner=runner).reason, reason)
                self.assertEqual(calls, [('git', '--version')])
        self.assertEqual(parse_git_version('git version 2.39.5 (Apple Git-154)\n'), (2, 39))
        self.assertIsNone(parse_git_version('junk git version 2.39.5'))

    def test_real_reads_strip_trace_environment_and_never_refresh_index(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repo = self.setup_repo(root)
            trace = root / 'trace-marker'
            index = repo / '.git/index'
            before = (index.read_bytes(), index.stat().st_mtime_ns)
            (repo / 'file.txt').write_text('new\n')
            calls = []
            def runner(request):
                calls.append(request)
                return run_command(request)
            with patch.dict(os.environ, {'GIT_TRACE': str(trace), 'GIT_EXTERNAL_DIFF': 'bad-helper',
                                          'GIT_CONFIG_COUNT': '1', 'GIT_CONFIG_KEY_0': 'core.fsmonitor',
                                          'GIT_CONFIG_VALUE_0': 'bad-helper'}):
                status = git_status_porcelain(repo, runner=runner)
                shown = git_show_file(repo, 'HEAD', 'file.txt', runner=runner)
            self.assertTrue(status.ok, status)
            self.assertIn(' M file.txt', status.stdout)
            self.assertTrue(shown.ok, shown)
            self.assertEqual(shown.stdout, 'old\n')
            self.assertFalse(trace.exists())
            self.assertEqual(before, (index.read_bytes(), index.stat().st_mtime_ns))
            self.assertTrue(all(req.env_allowlist == () and dict(req.env_overrides) == SAFE_GIT_ENV for req in calls))
            self.assertIn('--ignore-submodules=all', calls[2].argv)
            self.assertIn('--no-ext-diff', calls[-1].argv)
            self.assertIn('--no-textconv', calls[-1].argv)

    def test_real_marker_helpers_and_indirect_modes_refuse_before_content(self):
        cases = {
            'external_diff_unsupported': '[diff]\nexternal={helper}\n',
            'diff_helper_unsupported': '[diff "fixture"]\ntextconv={helper}\n',
            'filter_helper_unsupported': '[filter "fixture"]\nclean={helper}\nsmudge={helper}\nprocess={helper}\n',
            'fsmonitor_unsupported': '[core]\nfsmonitor={helper}\n',
            'partial_clone_unsupported': '[remote "origin"]\npromisor=true\n',
            'git_config_includes_unsupported': '[includeIf "gitdir:**"]\npath={include}\n',
            'worktree_config_unsupported': '[extensions]\nworktreeConfig=true\n',
            'submodules_unsupported': '[submodule "fixture"]\npath=child\n',
        }
        for reason, config in cases.items():
            with self.subTest(reason=reason), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                repo = self.setup_repo(root)
                marker = root / 'helper-ran'
                helper = root / 'helper'
                helper.write_text('#!/bin/sh\ntouch ' + str(marker) + '\n')
                helper.chmod(0o700)
                include = root / 'included-config'
                include.write_text('[core]\nfsmonitor=' + str(helper) + '\n')
                with (repo / '.git/config').open('a') as handle:
                    handle.write(config.format(helper=helper, include=include))
                (repo / '.gitattributes').write_text('file.txt filter=fixture diff=fixture\n')
                (repo / 'file.txt').write_text('changed\n')
                self.assertEqual(git_status_porcelain(repo).reason, reason)
                self.assertEqual(git_show_file(repo, 'HEAD', 'file.txt').reason, reason)
                self.assertFalse(marker.exists())

    def test_linked_gitdir_and_promisor_pack_refusal(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            (repo / '.git').write_text('gitdir: /outside\n')
            self.assertEqual(git_status_porcelain(repo).reason, 'linked_git_dir_unsupported')
        with tempfile.TemporaryDirectory() as tmp:
            repo = self.setup_repo(Path(tmp))
            (repo / '.git/objects/pack/fake.promisor').write_text('')
            self.assertEqual(git_status_porcelain(repo).reason, 'partial_clone_unsupported')

    def test_success_exit_with_truncated_output_is_not_evidence(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = self.setup_repo(Path(tmp))
            def runner(request):
                if tuple(request.argv) == ('git', '--version'):
                    return result(request, 'git version 2.39.5')
                if 'config' in request.argv:
                    return result(request)
                return replace(result(request), overflowed=True, stdout_truncated=True)
            self.assertFalse(git_status_porcelain(repo, runner=runner).ok)

    def test_unsafe_show_arguments_never_start_git(self):
        for revision, path in [('-anything', 'file'), ('HEAD', '../escape'), ('HEAD', '/absolute')]:
            def runner(request):
                self.fail('unsafe input spawned Git')
            self.assertEqual(git_show_file('.', revision, path, runner=runner).reason, 'unsafe_revision_or_path')
