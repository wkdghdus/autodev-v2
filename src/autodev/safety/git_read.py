"""Allowlisted Git reads for ordinary local repositories only."""
from __future__ import annotations

import re
import hashlib
import os
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from .runner import CommandRequest, CommandResult, run_command


SAFE_GIT_ENV = {"GIT_OPTIONAL_LOCKS": "0", "GIT_CONFIG_GLOBAL": "/dev/null",
                "GIT_CONFIG_SYSTEM": "/dev/null", "GIT_CONFIG_NOSYSTEM": "1",
                "GIT_TERMINAL_PROMPT": "0", "GIT_NO_LAZY_FETCH": "1",
                "GIT_NO_REPLACE_OBJECTS": "1", "PATH": "/usr/bin:/bin"}
Runner = Callable[[CommandRequest], CommandResult]


@dataclass(frozen=True)
class GitReadResult:
    ok: bool
    reason: str
    stdout: str = ""
    stderr: str = ""


def parse_git_version(text: str) -> tuple[int, int] | None:
    match = re.fullmatch(r"git version (\d+)\.(\d+)(?:\.\d+)?(?: \([^\n]*\))?\s*", text)
    return (int(match[1]), int(match[2])) if match else None


def _request(repo: Path, argv: tuple[str, ...], canaries: tuple[str, ...]) -> CommandRequest:
    return CommandRequest(argv, repo, env_allowlist=(), env_overrides=SAFE_GIT_ENV,
                          canaries=canaries, timeout_seconds=10)


def _successful(result: CommandResult) -> bool:
    return result.returncode == 0 and not (result.timed_out or result.overflowed or result.killed
                                          or result.stdout_truncated or result.stderr_truncated)


def _preflight(repo: Path, runner: Runner, canaries: tuple[str, ...]) -> str | None:
    version = runner(_request(repo, ("git", "--version"), canaries))
    if not _successful(version):
        return "git_version_failed"
    parsed = parse_git_version(version.stdout)
    if parsed is None:
        return "git_version_unparseable"
    if parsed < (2, 36):
        return "git_version_too_old"
    git = repo / ".git"
    if git.is_symlink() or not git.is_dir():
        return "linked_git_dir_unsupported" if git.exists() else "not_a_git_repository"
    if (git / "config").is_symlink() or not (git / "config").is_file():
        return "git_config_unsupported"
    if (repo / ".gitmodules").exists() or (repo / ".gitmodules").is_symlink():
        return "submodules_unsupported"
    if ((git / "commondir").exists() or (git / "config.worktree").exists()):
        return "worktree_config_unsupported"
    objects = git / "objects"
    if (objects.is_symlink() or (objects / 'info').is_symlink() or (objects / 'pack').is_symlink()
            or any((objects / "info" / name).exists() or (objects / "info" / name).is_symlink()
                   for name in ("alternates", "http-alternates"))):
        return "partial_clone_unsupported"
    pack = objects / 'pack'
    if pack.is_dir():
        with os.scandir(pack) as iterator:
            for count, entry in enumerate(iterator, 1):
                if count > 2000:
                    return 'git_metadata_limit'
                if entry.name.endswith('.promisor'):
                    return 'partial_clone_unsupported'
    result = runner(_request(repo, ("git", "-C", str(repo), "config", "--local", "--null",
                                   "--list", "--no-includes"), canaries))
    if not _successful(result):
        return "git_config_unparseable"
    for entry in result.stdout.split('\x00'):
        if not entry:
            continue
        key, _separator, value = entry.partition('\n')
        key = key.lower()
        if key.startswith("include.") or key.startswith("includeif."):
            return "git_config_includes_unsupported"
        if key.startswith("filter."):
            return "filter_helper_unsupported"
        if key == "diff.external":
            return "external_diff_unsupported"
        if key.startswith("diff.") and key.rsplit('.', 1)[-1] in {"command", "textconv"}:
            return "diff_helper_unsupported"
        if key == "core.fsmonitor" and value.lower() not in {"false", "0", "no", "off"}:
            return "fsmonitor_unsupported"
        if key.startswith("extensions."):
            return "worktree_config_unsupported" if key.endswith("worktreeconfig") else "partial_clone_unsupported"
        if key.endswith(".promisor") or key.endswith(".partialclonefilter"):
            return "partial_clone_unsupported"
        if key.startswith("submodule.") or key == "status.submodulesummary":
            return "submodules_unsupported"
        if key in {"core.worktree", "core.alternateRefsCommand".lower()}:
            return "git_config_unsupported"
    return None


def _read(repo: Path | str, args: tuple[str, ...], runner: Runner, canaries: tuple[str, ...]) -> GitReadResult:
    try:
        repo = Path(repo).absolute()
        if not repo.is_dir():
            return GitReadResult(False, "not_a_git_repository")
        reason = _preflight(repo, runner, canaries)
        if reason:
            return GitReadResult(False, reason)
        argv = ("git", "--no-pager", "-c", "core.fsmonitor=false", "-c", "core.untrackedCache=false",
                "-C", str(repo), *args)
        result = runner(_request(repo, argv, canaries))
        return GitReadResult(_successful(result), "ok" if _successful(result) else "git_read_failed",
                             result.stdout, result.stderr)
    except (OSError, ValueError):
        return GitReadResult(False, "git_read_unavailable")


def git_status_porcelain(repo: Path | str, *, runner: Runner = run_command,
                         canaries: tuple[str, ...] = ()) -> GitReadResult:
    return _read(repo, ("status", "--porcelain=v1", "--untracked-files=no", "--ignore-submodules=all"), runner, canaries)


def git_show_file(repo: Path | str, revision: str, path: str, *, runner: Runner = run_command,
                  canaries: tuple[str, ...] = ()) -> GitReadResult:
    if (not isinstance(revision, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_./-]*", revision)
            or not isinstance(path, str) or not path or path.startswith(('-', '/'))
            or '\x00' in path or ':' in path or '..' in Path(path).parts):
        return GitReadResult(False, "unsafe_revision_or_path")
    return _read(repo, ("show", "--no-ext-diff", "--no-textconv", f"{revision}:{path}"), runner, canaries)


# AD-03 reads use documented expected nonzero statuses, never generic success.
# References: git-scm.com/docs/{git-check-ignore,git-ls-files,git-symbolic-ref,
# git-rev-parse,git-show-ref,gitignore}. Host excludes are deliberately disabled.
@dataclass(frozen=True)
class GitRepositoryState:
    ok: bool
    reason: str
    state: str = "unsafe"
    revision: str | None = None
    branch: str | None = None
    dirty: bool = False
    common_dir: str | None = None
    config_sha256: str | None = None
    index_sha256: str | None = None
    status_sha256: str | None = None


@dataclass(frozen=True)
class GitTrackedPaths:
    ok: bool
    reason: str
    paths: tuple[str, ...] = ()


@dataclass(frozen=True)
class IgnoreObservation:
    path: str
    ignored: bool
    source: str = ""
    line: int | None = None
    pattern: str = ""


@dataclass(frozen=True)
class GitIgnoreResult:
    ok: bool
    reason: str
    observations: tuple[IgnoreObservation, ...] = ()


@dataclass(frozen=True)
class ManagedBucketEvidence:
    ok: bool
    reason: str
    strategy: str = "unknown"
    bucket: str | None = None
    tracked_paths: tuple[str, ...] = ()
    probes: tuple[str, ...] = ()
    observations: tuple[IgnoreObservation, ...] = ()
    ignore_original: bytes | None = None
    ignore_proposed: bytes | None = None
    proof_scope: str = "unverified"
    ignore_source_hashes: tuple[tuple[str, str | None], ...] = ()
    ignore_content_bytes: int = 0
    ignore_content_limit: int = 4194304


def _complete(result: CommandResult, statuses: tuple[int, ...] = (0,)) -> bool:
    return result.returncode in statuses and not (result.timed_out or result.overflowed or result.killed
            or result.stdout_truncated or result.stderr_truncated) and '\ufffd' not in result.stdout \
            and '[REDACTED]' not in result.stdout


def _passive(repo: Path, args: tuple[str, ...], runner: Runner,
             canaries: tuple[str, ...], stdin_bytes: bytes | None = None) -> CommandResult:
    argv = ("git", "--no-pager", "-c", "core.fsmonitor=false", "-c", "core.untrackedCache=false",
            "-c", "core.excludesFile=/dev/null", "-C", str(repo), *args)
    request = _request(repo, argv, canaries)
    if stdin_bytes is not None:
        from dataclasses import replace
        request = replace(request, stdin_bytes=stdin_bytes)
    return runner(request)


def _safe_root(repo: Path | str) -> Path:
    root = Path(repo).absolute()
    if not root.is_dir() or any(path.is_symlink() for path in (root, *root.parents)):
        raise ValueError("unsafe repository root")
    return root


def _literal_path(path: str) -> bool:
    if not isinstance(path, str):
        return False
    try:
        encoded = path.encode('utf-8')
    except UnicodeError:
        return False
    if (not path or len(encoded) > 4096
            or path.startswith(('/', '-')) or any(ord(c) < 32 or ord(c) == 127 for c in path)
            or any(c in path for c in '*?[]\\:!#$`{}()<>|;&')
            or any(part in {'', '.', '..'} or part.strip() != part for part in path.split('/'))):
        return False
    return True


def _safe_components(root: Path, relative: str) -> None:
    current = root
    parts = relative.split('/')
    for index, part in enumerate(parts):
        current /= part
        if current.is_symlink() or (index < len(parts) - 1 and current.exists() and not current.is_dir()):
            raise ValueError("symlink path")


def _bounded_bytes(path: Path, *, limit: int = 131072, single_link: bool = False) -> bytes | None:
    try:
        before = path.lstat()
    except FileNotFoundError:
        return None
    if (not stat.S_ISREG(before.st_mode) or before.st_size > limit
            or (single_link and before.st_nlink != 1)):
        raise ValueError("unsupported bounded file")
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, 'rb') as handle:
        info = os.fstat(handle.fileno())
        if ((before.st_dev, before.st_ino) != (info.st_dev, info.st_ino)
                or not stat.S_ISREG(info.st_mode) or info.st_size > limit
                or (single_link and info.st_nlink != 1)):
            raise ValueError("unsupported bounded file")
        data = handle.read(limit + 1)
    if len(data) > limit:
        raise ValueError("file limit")
    return data


def _sha(data: bytes | None) -> str | None:
    return None if data is None else hashlib.sha256(data).hexdigest()


def _valid_branch(branch: str) -> bool:
    return (branch.startswith('refs/heads/') and _literal_path(branch)
            and '..' not in branch and '@{' not in branch and not branch.endswith('.')
            and not any(char.isspace() or char in '~^' for char in branch)
            and not any(part.startswith('.') or part.endswith('.lock') for part in branch.split('/')))


def _metadata_guard(root: Path) -> None:
    """Bound indirect local metadata before letting Git interpret it."""
    if (root / '.git').is_symlink() or not (root / '.git').is_dir():
        return  # The existing preflight owns linked/non-Git diagnostics.
    for relative in ('.git/config', '.git/index', '.git/HEAD', '.git/packed-refs',
                     '.git/refs', '.git/objects/info', '.git/objects/pack'):
        _safe_components(root, relative)
    head = _bounded_bytes(root / '.git/HEAD')
    _bounded_bytes(root / '.git/packed-refs')
    if head and head.startswith(b'ref: '):
        branch = head[5:].decode('utf-8', errors='strict').strip()
        if not _valid_branch(branch):
            raise ValueError('unsupported symbolic HEAD')
        _safe_components(root, '.git/' + branch)
        reference = _bounded_bytes(root / '.git' / branch)
        if reference is not None and reference.startswith(b'ref: '):
            raise ValueError('indirect symbolic branch')


def git_repository_state(repo: Path | str, *, runner: Runner = run_command,
                         canaries: tuple[str, ...] = ()) -> GitRepositoryState:
    """Classify only ordinary roots; a failed HEAD lookup alone is never unborn."""
    try:
        root = _safe_root(repo)
        if not (root / '.git').exists() and not (root / '.git').is_symlink():
            if (root / 'HEAD').exists() and (root / 'objects').is_dir() and (root / 'config').exists():
                return GitRepositoryState(False, 'bare_repository_unsupported')
            return GitRepositoryState(True, 'not_a_git_repository', 'non_git')
        _metadata_guard(root)
        reason = _preflight(root, runner, canaries)
        if reason:
            return GitRepositoryState(False, reason)
        config = _bounded_bytes(root / '.git/config')
        index = _bounded_bytes(root / '.git/index', limit=4194304)
        bare = _passive(root, ('rev-parse', '--is-bare-repository'), runner, canaries)
        if not _complete(bare) or bare.stdout.strip() != 'false':
            return GitRepositoryState(False, 'bare_repository_unsupported' if bare.stdout.strip() == 'true'
                                      else 'git_metadata_unknown')
        symbolic = _passive(root, ('symbolic-ref', '--quiet', 'HEAD'), runner, canaries)
        head = _passive(root, ('rev-parse', '--verify', '--quiet', 'HEAD^{commit}'), runner, canaries)
        if not _complete(symbolic, (0, 1)) or not _complete(head, (0, 1)):
            return GitRepositoryState(False, 'git_head_unknown')
        branch = symbolic.stdout.strip() if symbolic.returncode == 0 else None
        if branch is not None and not _valid_branch(branch):
            return GitRepositoryState(False, 'git_head_unknown')
        revision = head.stdout.strip() if head.returncode == 0 else None
        if revision is not None and re.fullmatch('[0-9a-f]{40}|[0-9a-f]{64}', revision) is None:
            return GitRepositoryState(False, 'git_head_unknown')
        if revision is None:
            if branch is None:
                return GitRepositoryState(False, 'git_head_unknown')
            absent = _passive(root, ('show-ref', '--verify', '--quiet', branch), runner, canaries)
            if not _complete(absent, (1,)):
                return GitRepositoryState(False, 'git_head_unknown')
            state = 'unborn'
        else:
            state = 'attached' if branch else 'detached'
        status = _passive(root, ('status', '--porcelain=v1', '-z', '--untracked-files=no',
                                 '--ignore-submodules=all'), runner, canaries)
        if not _complete(status):
            return GitRepositoryState(False, 'git_status_unknown')
        return GitRepositoryState(True, 'ok', state, revision, branch, bool(status.stdout),
                str((root / '.git').resolve()), _sha(config), _sha(index), _sha(status.stdout.encode('utf-8')))
    except (OSError, ValueError, UnicodeError):
        return GitRepositoryState(False, 'git_read_unavailable')


def git_tracked_paths(repo: Path | str, bucket: str, *, runner: Runner = run_command,
                      canaries: tuple[str, ...] = ()) -> GitTrackedPaths:
    if not _literal_path(bucket):
        return GitTrackedPaths(False, 'unsafe_bucket_path')
    try:
        root = _safe_root(repo)
        _safe_components(root, bucket)
        _metadata_guard(root)
        reason = _preflight(root, runner, canaries)
        if reason:
            return GitTrackedPaths(False, reason)
        result = _passive(root, ('ls-files', '--cached', '--full-name', '-z', '--', bucket), runner, canaries)
        if not _complete(result) or (result.stdout and not result.stdout.endswith('\x00')):
            return GitTrackedPaths(False, 'git_index_unknown')
        paths = tuple(sorted(set(result.stdout.rstrip('\x00').split('\x00')))) if result.stdout else ()
        if any(not (path == bucket or path.startswith(bucket + '/')) for path in paths):
            return GitTrackedPaths(False, 'git_index_unknown')
        return GitTrackedPaths(True, 'ok', paths)
    except (OSError, ValueError, UnicodeError):
        return GitTrackedPaths(False, 'git_read_unavailable')


def git_check_ignore(repo: Path | str, paths: tuple[str, ...], *, runner: Runner = run_command,
                      canaries: tuple[str, ...] = ()) -> GitIgnoreResult:
    if not paths or len(paths) > 2001 or any(not _literal_path(path.rstrip('/')) for path in paths):
        return GitIgnoreResult(False, 'unsafe_ignore_path')
    try:
        data = ('\x00'.join(paths) + '\x00').encode('utf-8')
        if len(data) > 65536:
            return GitIgnoreResult(False, 'ignore_probe_limit')
        root = _safe_root(repo)
        for path in paths:
            _safe_components(root, path.rstrip('/'))
        _metadata_guard(root)
        reason = _preflight(root, runner, canaries)
        if reason:
            return GitIgnoreResult(False, reason)
        result = _passive(root, ('check-ignore', '--no-index', '--verbose', '--non-matching',
                                 '-z', '--stdin'), runner, canaries, data)
        # check-ignore exit 1 is a complete negative observation, 128 is unknown.
        if not _complete(result, (0, 1)) or not result.stdout.endswith('\x00'):
            return GitIgnoreResult(False, 'git_ignore_unknown')
        fields = result.stdout[:-1].split('\x00')
        if len(fields) != 4 * len(paths):
            return GitIgnoreResult(False, 'git_ignore_unknown')
        observations = []
        for offset, path in zip(range(0, len(fields), 4), paths):
            source, line, pattern, observed = fields[offset:offset + 4]
            if observed != path or (source and not line.isdecimal()) or (not source and (line or pattern)):
                return GitIgnoreResult(False, 'git_ignore_unknown')
            observations.append(IgnoreObservation(path, bool(source and pattern and not pattern.startswith('!')),
                                                 source, int(line) if line else None, pattern))
        return GitIgnoreResult(True, 'ok', tuple(observations))
    except (OSError, ValueError, UnicodeError):
        return GitIgnoreResult(False, 'git_read_unavailable')


def _bucket_probes(root: Path, bucket: str) -> tuple[str, ...]:
    """Directory exclusion plus all known descendants; exceeding limits is unknown."""
    probes = [bucket + '/']
    directory = root / bucket
    if directory.exists() and not directory.is_dir():
        raise ValueError('bucket is not a directory')
    pending = [(directory, 0)] if directory.exists() else []
    while pending:
        directory, depth = pending.pop()
        entries = []
        with os.scandir(directory) as iterator:
            for entry in iterator:
                if len(probes) + len(entries) >= 2001:
                    raise ValueError('bucket probe limit')
                entries.append(entry)
        for entry in sorted(entries, key=lambda item: item.name):
            relative = str(Path(entry.path).relative_to(root))
            if not _literal_path(relative) or entry.is_symlink():
                raise ValueError('unsafe bucket descendant')
            is_dir = entry.is_dir(follow_symlinks=False)
            if not is_dir and not entry.is_file(follow_symlinks=False):
                raise ValueError('special bucket descendant')
            probes.append(relative + ('/' if is_dir else ''))
            if is_dir:
                if depth >= 4:
                    raise ValueError('bucket depth limit')
                pending.append((Path(entry.path), depth + 1))
    return tuple(sorted(probes))


def managed_bucket_evidence(repo: Path | str, bucket: str | None, *,
                            excluded_paths: tuple[str, ...] = (), runner: Runner = run_command,
                            canaries: tuple[str, ...] = (),
                            read_bytes: Callable[[str], bytes | None] | None = None) -> ManagedBucketEvidence:
    if bucket is None:
        return ManagedBucketEvidence(True, 'worktree_strategy_unknown')
    forbidden = ('.git', '.agent', 'docs', 'context', 'requirements', 'plans', 'milestones', 'tests', 'test',
                 *excluded_paths)
    if not _literal_path(bucket) or any(bucket == path or bucket.startswith(path + '/')
            or path.startswith(bucket + '/') for path in forbidden):
        return ManagedBucketEvidence(False, 'unsafe_bucket_path', 'in_repository', bucket)
    try:
        root = _safe_root(repo)
        _safe_components(root, bucket)
        tracked = git_tracked_paths(root, bucket, runner=runner, canaries=canaries)
        if not tracked.ok:
            return ManagedBucketEvidence(False, tracked.reason, 'in_repository', bucket)
        if tracked.paths:
            return ManagedBucketEvidence(False, 'tracked_bucket_paths', 'in_repository', bucket, tracked.paths)
        probes = _bucket_probes(root, bucket)
        # Refuse indirect ignore reads before Git can follow them.
        ignore_paths = {root / '.gitignore', root / '.git/info/exclude'}
        for probe in probes:
            parent = (root / probe.rstrip('/')).parent
            while parent != root:
                ignore_paths.add(parent / '.gitignore')
                parent = parent.parent
        ignore_source_hashes = []
        ignore_content_bytes = 0
        ignore_contents = {}
        if len(ignore_paths) > 2000:
            raise ValueError('ignore source limit')
        for path in sorted(ignore_paths):
            relative = str(path.relative_to(root))
            _safe_components(root, relative)
            limit = min(131072, 4194304 - ignore_content_bytes)
            if read_bytes is None:
                content = _bounded_bytes(path, limit=limit, single_link=relative == '.gitignore')
            else:
                try:
                    info = path.lstat()
                except FileNotFoundError:
                    info = None
                if info is not None and (not stat.S_ISREG(info.st_mode) or info.st_size > limit
                        or (relative == '.gitignore' and info.st_nlink != 1)):
                    raise ValueError('unsupported ignore source')
                content = read_bytes(relative)
                if (info is not None and content is None) or (content is not None
                        and (type(content) is not bytes or len(content) > limit)):
                    raise ValueError('ignore source unreadable')
            if content is not None:
                content.decode('utf-8', errors='strict')
                if b'\x00' in content:
                    raise ValueError('unsupported ignore encoding')
                ignore_content_bytes += len(content)
            ignore_contents[relative] = content
            ignore_source_hashes.append((relative, _sha(content)))
        original = ignore_contents['.gitignore']
        ignored = git_check_ignore(root, probes, runner=runner, canaries=canaries)
        if not ignored.ok:
            return ManagedBucketEvidence(False, ignored.reason, 'in_repository', bucket, (), probes)
        complete = all(item.ignored for item in ignored.observations)
        proposed = None
        if not complete:
            existing = original or b''
            newline = b'\r\n' if b'\r\n' in existing else b'\n'
            separator = b'' if not existing or existing.endswith(b'\n') else newline
            proposed = existing + separator + ('/' + bucket + '/').encode('utf-8') + newline
        return ManagedBucketEvidence(True, 'already_ignored' if complete else 'ignore_append_required',
                'in_repository', bucket, (), probes, ignored.observations, original, proposed,
                'bucket_directory_and_all_bounded_known_descendants;host_excludes_disabled',
                tuple(ignore_source_hashes), ignore_content_bytes)
    except (OSError, ValueError, UnicodeError):
        return ManagedBucketEvidence(False, 'bucket_evidence_unknown', 'in_repository', bucket)


def git_bucket_postcheck(repo: Path | str, bucket: str, *, runner: Runner = run_command,
                         canaries: tuple[str, ...] = ()) -> bool:
    evidence = managed_bucket_evidence(repo, bucket, runner=runner, canaries=canaries)
    return evidence.ok and evidence.reason == 'already_ignored' and evidence.ignore_proposed is None
