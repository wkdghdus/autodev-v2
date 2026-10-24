"""Observe init's real effects in a child guarded before application import.

The Python audit guard controls the parent process. Git's independent effects
are checked by complete repository/home snapshots and executable canaries.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]


def _snapshot(root: Path) -> dict:
    result = {}
    for path in sorted(root.rglob("*")):
        info = path.lstat()
        relative = path.relative_to(root).as_posix()
        if path.is_symlink():
            result[relative] = ("symlink", os.readlink(path))
        elif path.is_file():
            result[relative] = ("file", stat.S_IMODE(info.st_mode),
                                hashlib.sha256(path.read_bytes()).hexdigest())
        else:
            result[relative] = ("directory", stat.S_IMODE(info.st_mode))
    return result


# All modules used by the harness load before the guard; all autodev modules
# load after it. No application helper supplies any part of the allowlist.
CHILD = r'''
import contextlib
import io
import json
import os
from pathlib import Path
import socket
import stat
import subprocess
import sys
import sysconfig

cfg = json.loads(sys.argv[1])
repo = Path(cfg['repo']).resolve()
source = Path(cfg['source']).resolve()
state = repo / '.agent' / '.init-state'
repository_ancestors = set(repo.parents)
read_roots = (repo, source, *(Path(sysconfig.get_path(key)).resolve()
               for key in ('stdlib', 'platstdlib')))
targets = {repo / path for path in cfg.get('targets', [])}
parents = {path.parent for path in targets}
attempts = []
reads = []
writes = []
processes = []
phase = 'positive-control'

def resolved(path):
    if isinstance(path, int):
        # fdopen does not acquire authority: its fd must already have passed
        # the path-based open check, and directory descriptors are read-only.
        return descriptor_paths.get(path)
    return Path(os.fsdecode(path)).resolve()

def within(path, root):
    return path == root or path.is_relative_to(root)

def allowed_write(path):
    return cfg['apply'] and (path in targets or within(path, state)
        or path in parents or path == repo / '.agent'
        or (path.parent in parents and path.name.startswith('.autodev-init-')))

def reject(event, detail):
    attempts.append({'phase': phase, 'event': event, 'detail': str(detail)})
    raise PermissionError('AD03 effect guard denied ' + event)

def git_allowed(executable, argv, cwd, env):
    # Literal typed read shapes. There is deliberately no general git prefix.
    if not cfg.get('git') or executable != 'git' or cwd != str(repo):
        return False
    if not isinstance(argv, (list, tuple)):
        return False
    fixed = {
        ('git', '--version'),
        ('git', '-C', str(repo), 'config', '--local', '--null', '--list', '--no-includes'),
    }
    prefix = ('git', '--no-pager', '-c', 'core.fsmonitor=false', '-c',
              'core.untrackedCache=false', '-c', 'core.excludesFile=/dev/null',
              '-C', str(repo))
    tails = {
        ('status', '--porcelain=v1', '-z', '--untracked-files=no', '--ignore-submodules=all'),
        ('rev-parse', '--verify', '--quiet', 'HEAD^{commit}'),
        ('rev-parse', '--is-bare-repository'),
        ('symbolic-ref', '--quiet', 'HEAD'),
        ('show-ref', '--verify', '--quiet', 'refs/heads/master'),
        ('show-ref', '--verify', '--quiet', 'refs/heads/main'),
    }
    if tuple(argv) not in fixed and tuple(argv) not in {prefix + tail for tail in tails}:
        return False
    required = {'GIT_OPTIONAL_LOCKS': '0', 'GIT_CONFIG_GLOBAL': '/dev/null',
                'GIT_CONFIG_SYSTEM': '/dev/null', 'GIT_CONFIG_NOSYSTEM': '1',
                'GIT_TERMINAL_PROMPT': '0', 'GIT_NO_LAZY_FETCH': '1',
                'GIT_NO_REPLACE_OBJECTS': '1', 'PATH': '/usr/bin:/bin'}
    return isinstance(env, dict) and all(env.get(k) == v for k, v in required.items())

descriptor_paths = {}
pending_open = None
real_os_open = os.open

def tracked_open(path, flags, mode=0o777, *, dir_fd=None):
    global pending_open
    base = descriptor_paths.get(dir_fd) if dir_fd is not None else Path.cwd()
    if base is None:
        reject('open', 'untracked-directory-descriptor')
    full = Path(os.fsdecode(path))
    full = full if full.is_absolute() else base / full
    previous = pending_open
    pending_open = full.resolve()
    try:
        fd = real_os_open(path, flags, mode, dir_fd=dir_fd)
    finally:
        pending_open = previous
    descriptor_paths[fd] = full.resolve()
    return fd

def audit(event, args):
    if event == 'open':
        raw, mode, flags = args
        if isinstance(raw, int) and stat.S_ISFIFO(os.fstat(raw).st_mode):
            # Popen wraps its anonymous stdout/stderr pipes with fdopen.
            return
        path = pending_open if pending_open is not None else resolved(raw)
        write = any(c in (mode or '') for c in 'wax+') or bool(
            (flags or 0) & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_APPEND))
        if path is None:
            reject(event, 'untracked-descriptor')
        # subprocess.DEVNULL opens the OS sink read/write. It is neither a
        # repository/temp-file write nor authority to open any other device.
        if path == Path('/dev/null'):
            return
        if (pending_open is not None and path in repository_ancestors and not write
                and flags & (os.O_DIRECTORY | os.O_NOFOLLOW) == (os.O_DIRECTORY | os.O_NOFOLLOW)):
            # Safety's descriptor walk anchors the canonical repository at '/'.
            # This grants directory handles only, never ancestor file contents,
            # listings, mutation, or arbitrary sibling directory traversal.
            reads.append(str(path) + ' [directory-descriptor]')
            return
        if write:
            if not allowed_write(path):
                reject(event, path)
            writes.append({'event': event, 'path': str(path)})
        elif path != Path('/dev/null') and not any(within(path, root) for root in read_roots):
            reject('read', path)
        else:
            reads.append(str(path))
    elif event in {'os.listdir', 'os.scandir'}:
        path = resolved(args[0] if args and args[0] is not None else Path.cwd())
        if path is None or not any(within(path, root) for root in read_roots):
            reject(event, path if path is not None else 'untracked-descriptor')
    elif event == 'subprocess.Popen':
        executable, argv, cwd, env = args
        if not git_allowed(executable, argv, cwd, env):
            reject(event, argv)
        processes.append(list(argv))
    elif event.startswith('socket.') or event in {
        'os.system', 'os.posix_spawn', 'os.fork', 'os.forkpty', 'os.exec',
        'os.startfile', 'pty.spawn', 'ctypes.dlopen',
    }:
        reject(event, event)
    elif event == 'import' and args[0].split('.')[0] in {
        'openai', 'anthropic', 'mcp', 'hermes', 'nous', 'gjc',
    }:
        reject(event, args[0])
    elif event == 'exec':
        filename = args[0].co_filename
        if filename and not filename.startswith('<') and within(Path(filename).resolve(), repo):
            reject(event, filename)
    elif event in {
        'os.remove', 'os.rmdir', 'os.mkdir', 'os.rename', 'os.link',
        'os.symlink', 'os.truncate', 'os.chmod', 'os.chown', 'os.utime',
    }:
        if event in {'os.symlink', 'os.chown'}:
            reject(event, event)
        paths = [arg for arg in args[:2] if isinstance(arg, (str, bytes, os.PathLike))]
        # remove/rmdir/rename/link can use a directory fd. Resolve it using
        # descriptors already admitted by the guarded os.open wrapper.
        for index, raw in enumerate(paths):
            path = Path(os.fsdecode(raw))
            fd_index = 2 + index if event in {'os.rename', 'os.link'} else len(args) - 1
            dir_fd = args[fd_index] if fd_index < len(args) else -1
            if not path.is_absolute() and isinstance(dir_fd, int) and dir_fd >= 0:
                base = descriptor_paths.get(dir_fd)
                if base is None:
                    reject(event, 'untracked-directory-descriptor')
                path = base / path
            path = path.resolve()
            if not allowed_write(path):
                reject(event, path)
            writes.append({'event': event, 'path': str(path)})
        if not paths:
            path = resolved(args[0]) if args else None
            if path is None or not allowed_write(path):
                reject(event, 'untracked-descriptor')
            writes.append({'event': event, 'path': str(path)})

os.open = tracked_open
sys.addaudithook(audit)
controls = []

def ancestor_descriptor_list():
    descriptor = os.open(repo.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.listdir(descriptor)
    finally:
        os.close(descriptor)

for label, action in (
    ('profile-read', lambda: Path(cfg['sentinel']).read_bytes()),
    ('profile-write', lambda: Path(cfg['sentinel']).write_bytes(b'changed')),
    ('lowlevel-write', lambda: os.open(cfg['sentinel'], os.O_WRONLY | os.O_TRUNC)),
    ('mkdir', lambda: os.mkdir(str(Path(cfg['sentinel']).parent / 'forbidden'))),
    ('ancestor-content-open', lambda: os.open(repo.parent, os.O_RDONLY)),
    ('ancestor-list', lambda: os.listdir(repo.parent)),
    ('ancestor-descriptor-list', ancestor_descriptor_list),
    ('process', lambda: subprocess.Popen(['sh', '-c', 'exit 0'])),
    ('system', lambda: os.system('exit 0')),
    ('network', lambda: socket.socket()),
):
    try:
        action()
    except PermissionError:
        controls.append(label)
    else:
        raise AssertionError('guard missed positive control: ' + label)
attempts.clear()
reads.clear()
phase = 'application'
from autodev.cli import main
stdout, stderr = io.StringIO(), io.StringIO()
with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
    try:
        code = main(['init', str(repo), *cfg['args']])
    except SystemExit as exc:
        code = exc.code
payload = {'code': code, 'stdout': stdout.getvalue(), 'stderr': stderr.getvalue(),
           'attempts': attempts, 'reads': reads, 'writes': writes,
           'processes': processes, 'controls': controls}
print(json.dumps(payload, sort_keys=True))
'''


class InitEffectsTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name).resolve()
        self.repo = self.base / "repository with spaces é"
        self.home = self.base / "home"
        self.config = self.base / "config"
        self.cwd = self.base / "launcher"
        for path in (self.repo, self.home, self.config, self.cwd):
            path.mkdir()
        for relative in (".profile", ".bashrc", ".zshrc", ".gitconfig",
                         ".nous/account.json", ".hermes/config.yaml", ".gjc/profile"):
            path = self.home / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(b"AD03 protected profile sentinel\n")
        (self.config / "account.json").write_bytes(b"AD03 protected config sentinel\n")
        self._hostile_metadata()

    def _hostile_metadata(self):
        canary = self.base / "PROJECT-CODE-EXECUTED"
        command = 'printf executed >> "' + str(canary) + '"'
        (self.repo / "package.json").write_text(json.dumps({
            "name": "passive-fixture", "scripts": {
                key: command for key in ("preinstall", "install", "prepare", "test", "build")}}))
        (self.repo / "Makefile").write_text("all test install:\n\t" + command + "\n")
        (self.repo / "pyproject.toml").write_text(
            '[build-system]\nrequires = []\nbuild-backend = "hostile_backend"\n'
            '[project]\nname = "passive-fixture"\nversion = "0.0.0"\n'
            '[project.scripts]\nfixture = "hostile_backend:run"\n')
        code = "from pathlib import Path\nPath(" + repr(str(canary)) + ").write_text('executed')\n"
        for name in ("hostile_backend.py", "conftest.py", "setup.py"):
            (self.repo / name).write_text(code)
        for name in (".envrc", ".env", ".tool-versions"):
            (self.repo / name).write_text(command + "\n")
        (self.repo / "AGENT.md").write_text("# Passive context\nRun no commands.\n")

    def child(self, *args, apply=False, git=False, targets=()):
        configuration = {
            "repo": str(self.repo), "source": str(ROOT / "src"),
            "sentinel": str(self.home / ".profile"), "args": list(args),
            "apply": apply, "git": git, "targets": list(targets),
        }
        result = subprocess.run(
            [sys.executable, "-B", "-c", CHILD, json.dumps(configuration)],
            cwd=self.cwd, env={"PATH": "/usr/bin:/bin", "HOME": str(self.home),
                "XDG_CONFIG_HOME": str(self.config), "PYTHONPATH": str(ROOT / "src"),
                "PYTHONDONTWRITEBYTECODE": "1", "LANG": "C.UTF-8"},
            capture_output=True, text=True, timeout=45, check=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        audit = json.loads(result.stdout)
        self.assertEqual(audit["attempts"], [], {key: audit[key] for key in
            ("attempts", "code", "processes", "writes", "stdout", "stderr")})
        self.assertEqual(set(audit["controls"]), {
            "profile-read", "profile-write", "lowlevel-write", "mkdir", "ancestor-content-open",
            "ancestor-list", "ancestor-descriptor-list", "process", "system", "network"})
        # json.loads rejects concatenated preliminary/final JSON envelopes.
        report = json.loads(audit["stdout"])
        return audit, report

    def test_hostile_metadata_preview_and_dry_run_have_zero_effects(self):
        before = _snapshot(self.base)
        first, report = self.child("--json")
        self.assertEqual(first["code"], 0, first)
        self.assertEqual(report["status"], "preview")
        self.assertFalse(report["lifecycle_ready"])
        for args in (("--json",), ("--json", "--dry-run")):
            audit, again = self.child(*args)
            self.assertEqual(audit["code"], 0, audit)
            self.assertEqual(audit["writes"], [])
            self.assertEqual(audit["processes"], [])
            self.assertEqual(again, report)
            self.assertEqual(_snapshot(self.base), before)
        self.assertFalse((self.repo / ".agent").exists())

    def test_digest_json_apply_confines_observed_writes_and_noop_is_inert(self):
        before = _snapshot(self.base)
        _, preview = self.child("--json", "--dry-run")
        targets = (".agent/PROJECT.yaml", ".agent/EXECUTION.yaml")
        digest = preview.get("digest", preview.get("proposal_digest"))
        self.assertIsInstance(digest, str)
        audit, applied = self.child("--json", "--apply", digest, "--yes",
                                    apply=True, targets=targets)
        self.assertEqual(audit["code"], 0, audit)
        self.assertEqual(applied["status"], "applied")
        self.assertEqual(applied["proposal"], preview)
        self.assertTrue(audit["writes"], "apply must expose actual audited writes")
        self.assertEqual(set(applied["alignment_changes"]), set(targets))
        self.assertTrue(applied["infrastructure_effects"])
        self.assertEqual(audit["processes"], [])
        after = _snapshot(self.base)
        for relative, value in before.items():
            self.assertEqual(after.get(relative), value, relative)
        added = set(after) - set(before)
        for relative in added:
            path = (self.base / relative).relative_to(self.repo).as_posix()
            self.assertTrue(path in {".agent", *targets} or path.startswith(".agent/.init-state"), path)
        for target in targets:
            self.assertTrue((self.repo / target).is_file())
        for args in (("--json",), ("--json", "--dry-run")):
            noop, report = self.child(*args)
            self.assertEqual(noop["code"], 0, noop)
            self.assertEqual(report["status"], "noop")
            self.assertEqual(noop["writes"], [])
            self.assertEqual(_snapshot(self.base), after)
        # Even explicit apply of a reviewed no-op cannot touch lock/state.
        noop, envelope = self.child("--json", "--apply", report["digest"], "--yes")
        self.assertEqual(noop["code"], 0, noop)
        self.assertEqual(envelope["status"], "noop")
        self.assertEqual(noop["writes"], [])
        self.assertEqual(_snapshot(self.base), after)

    def test_stale_digest_rejection_has_zero_state_or_alignment_writes(self):
        _, preview = self.child("--json")
        (self.repo / "ROADMAP.md").write_text("# A new discovery candidate\n")
        before = _snapshot(self.base)
        audit, report = self.child("--json", "--apply", preview["digest"], "--yes")
        self.assertEqual(audit["code"], 2, audit)
        self.assertEqual(report["status"], "stale_proposal")
        self.assertEqual(audit["writes"], [])
        self.assertEqual(audit["processes"], [])
        self.assertEqual(_snapshot(self.base), before)
        self.assertFalse((self.repo / ".agent").exists())

    def _git(self, *args):
        result = subprocess.run(["git", "-C", str(self.repo), *args],
            env={"PATH": "/usr/bin:/bin", "HOME": str(self.home),
                 "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_CONFIG_SYSTEM": "/dev/null"},
            capture_output=True, text=True, timeout=15, check=False)
        self.assertEqual(result.returncode, 0, result.stderr)

    @unittest.skipUnless(shutil.which("git"), "Git is required for real passive-probe audit")
    def test_real_git_probes_are_literal_allowlisted_and_hooks_remain_inert(self):
        self._git("init", "-q")
        canary = self.base / "GIT-HOOK-EXECUTED"
        for name in ("pre-commit", "post-checkout", "post-merge", "reference-transaction"):
            path = self.repo / ".git" / "hooks" / name
            path.write_text('#!/bin/sh\nprintf executed >> "' + str(canary) + '"\n')
            path.chmod(0o755)
        before = _snapshot(self.base)
        audit, report = self.child("--json", "--dry-run", git=True)
        self.assertEqual(audit["code"], 0, audit)
        self.assertEqual(report["status"], "preview")
        self.assertTrue(audit["processes"], "real Git path must actually exercise probes")
        self.assertEqual(audit["writes"], [])
        self.assertEqual(_snapshot(self.base), before)

    @unittest.skipUnless(shutil.which("git"), "Git is required for hostile-config audit")
    def test_git_fsmonitor_filter_and_include_canaries_are_never_activated(self):
        self._git("init", "-q")
        config = self.repo / ".git" / "config"
        original = config.read_bytes()
        helper = self.base / "git-helper"
        helper.write_text('#!/bin/sh\nprintf executed >> "' + str(self.base / "GIT-HELPER-EXECUTED") + '"\n')
        helper.chmod(0o755)
        include = self.home / "hostile-git-include"
        include.write_text('[core]\nfsmonitor = "' + str(helper) + '"\n')
        suffixes = (
            '\n[core]\nfsmonitor = "' + str(helper) + '"\n',
            '\n[filter "hostile"]\nclean = "' + str(helper) + '"\n',
            '\n[include]\npath = "' + str(include) + '"\n',
        )
        for suffix in suffixes:
            with self.subTest(config=suffix.splitlines()[1]):
                config.write_bytes(original + suffix.encode())
                before = _snapshot(self.base)
                audit, report = self.child("--json", "--dry-run", git=True)
                self.assertEqual(audit["code"], 2, audit)
                self.assertEqual(report["status"], "needs_input")
                self.assertEqual(audit["writes"], [])
                self.assertFalse(any("status" in argv for argv in audit["processes"]))
                self.assertEqual(_snapshot(self.base), before)


if __name__ == "__main__":
    unittest.main()
