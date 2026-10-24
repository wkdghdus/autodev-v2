"""Exact repository byte writes under a cooperative repository lock.

Rename cannot protect against an arbitrary writer between the final check and
rename. Absent targets instead use atomic link publication, which never clobbers.
"""
from __future__ import annotations

import os
import stat
import uuid
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path

from .types import CompareAndSwapError, UnsafePathError


MAX_FILE_BYTES = 128 * 1024


@dataclass(frozen=True)
class FileSnapshot:
    data: bytes | None
    mode: int
    inode: tuple[int, int] | None


def checked_root(root: Path | str) -> Path:
    root = Path(root).absolute()
    # A host-provided ancestor such as /tmp may be an alias; the selected root
    # itself must be an ordinary directory, and its canonical identity is bound.
    info = root.lstat()
    if not stat.S_ISDIR(info.st_mode) or root.is_symlink():
        raise UnsafePathError("repository root must be an ordinary directory")
    return root.resolve()


def target_path(root: Path, relative: str, *, missing_parents: bool = False) -> Path:
    rel = Path(relative)
    if (not relative or rel.is_absolute() or rel == Path('.') or '..' in rel.parts
            or '\x00' in relative or rel.as_posix() != relative
            or '.init-state' in rel.parts or '.git' in rel.parts):
        raise UnsafePathError("unsafe or reserved repository destination")
    current = root
    for part in rel.parts[:-1]:
        current = current / part
        try:
            info = current.lstat()
        except FileNotFoundError:
            if missing_parents:
                continue
            raise UnsafePathError("repository destination parent is missing") from None
        if not stat.S_ISDIR(info.st_mode):
            raise UnsafePathError("repository destination has a linked or special parent")
    return root / rel


def snapshot(root: Path, relative: str) -> FileSnapshot:
    try:
        with parent_descriptor(root, relative) as (parent, name):
            return _snapshot_at(parent, name)
    except FileNotFoundError:
        return FileSnapshot(None, 0o644, None)


@contextmanager
def parent_descriptor(root: Path, relative: str):
    """Walk each component under an open root; never resolve an ancestor link."""
    target_path(root, relative, missing_parents=True)
    descriptor = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for component in root.absolute().parts[1:]:
            child = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
        for component in Path(relative).parts[:-1]:
            child = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
        yield descriptor, Path(relative).name
    finally:
        os.close(descriptor)


def _snapshot_at(parent: int, name: str, *, allow_multiple_links: bool = False) -> FileSnapshot:
    try:
        info = os.stat(name, dir_fd=parent, follow_symlinks=False)
    except FileNotFoundError:
        return FileSnapshot(None, 0o644, None)
    if not stat.S_ISREG(info.st_mode) or (info.st_nlink != 1 and not allow_multiple_links):
        raise UnsafePathError("repository target must be a single-link regular file")
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=parent)
    try:
        opened = os.fstat(fd)
        if (opened.st_dev, opened.st_ino) != (info.st_dev, info.st_ino):
            raise CompareAndSwapError("repository target changed while opening")
        with os.fdopen(fd, 'rb', closefd=False) as handle:
            data = handle.read(MAX_FILE_BYTES + 1)
        after = os.fstat(fd)
        if len(data) > MAX_FILE_BYTES or after.st_size != len(data):
            raise UnsafePathError("repository target exceeds byte bound or changed")
        if (after.st_mtime_ns, after.st_ctime_ns) != (opened.st_mtime_ns, opened.st_ctime_ns):
            raise CompareAndSwapError("repository target changed while reading")
        return FileSnapshot(data, stat.S_IMODE(info.st_mode), (info.st_dev, info.st_ino))
    finally:
        os.close(fd)


def planned_stage(relative: str) -> str:
    return (Path(relative).parent / ('.autodev-init-' + uuid.uuid4().hex)).as_posix()


def stage(root: Path, relative: str, payload: bytes, mode: int, *, staging: str | None = None) -> tuple[str, tuple[int, int]]:
    if not isinstance(payload, bytes) or len(payload) > MAX_FILE_BYTES:
        raise UnsafePathError("proposed repository bytes exceed bound")
    staging = staging or planned_stage(relative)
    if Path(staging).parent != Path(relative).parent or not Path(staging).name.startswith('.autodev-init-'):
        raise UnsafePathError('invalid staging destination')
    with parent_descriptor(root, relative) as (parent, _name):
        fd = os.open(Path(staging).name, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW,
                     0o600, dir_fd=parent)
        try:
            os.fchmod(fd, mode & 0o7777)
            with os.fdopen(fd, 'wb', closefd=False) as handle:
                handle.write(payload)
                handle.flush()
                os.fsync(fd)
            info = os.fstat(fd)
            os.fsync(parent)
            return staging, (info.st_dev, info.st_ino)
        finally:
            os.close(fd)


def publish(root: Path, relative: str, staging: str, expected: FileSnapshot,
            *, staged: FileSnapshot) -> tuple[int, int]:
    if Path(staging).parent != Path(relative).parent:
        raise UnsafePathError('staging parent differs from destination')
    with parent_descriptor(root, relative) as (parent, name):
        observed_stage = _snapshot_at(parent, Path(staging).name)
        if observed_stage != staged:
            raise CompareAndSwapError('staged file changed before publication')
        current = _snapshot_at(parent, name)
        if current.data != expected.data or current.inode != expected.inode:
            raise CompareAndSwapError("repository target changed before publication")
        if expected.data is None:
            os.link(Path(staging).name, name, src_dir_fd=parent, dst_dir_fd=parent,
                    follow_symlinks=False)
            os.unlink(Path(staging).name, dir_fd=parent)
        else:
            os.replace(Path(staging).name, name, src_dir_fd=parent, dst_dir_fd=parent)
        info = os.stat(name, dir_fd=parent, follow_symlinks=False)
        os.fsync(parent)
        return (info.st_dev, info.st_ino)


def remove_owned_stage(root: Path, staging: str | None, inode: tuple[int, int] | None,
                       payload: bytes | None) -> None:
    if not staging or inode is None:
        return
    try:
        with parent_descriptor(root, staging) as (parent, name):
            observed = _snapshot_at(parent, name, allow_multiple_links=True)
            if observed.data is None:
                return
            if observed.inode == tuple(inode) and observed.data == payload:
                os.unlink(name, dir_fd=parent)
                os.fsync(parent)
            else:
                raise CompareAndSwapError('staging ownership changed during recovery')
    except FileNotFoundError:
        return


def remove_owned_target(root: Path, relative: str, expected: FileSnapshot) -> None:
    with parent_descriptor(root, relative) as (parent, name):
        current = _snapshot_at(parent, name)
        if current != expected:
            raise CompareAndSwapError('rollback target changed')
        os.unlink(name, dir_fd=parent)
        os.fsync(parent)


def directory_identity(root: Path, relative: str) -> tuple[int, int] | None:
    try:
        with parent_descriptor(root, relative) as (parent, name):
            info = os.stat(name, dir_fd=parent, follow_symlinks=False)
            if not stat.S_ISDIR(info.st_mode):
                raise UnsafePathError('parent is not an ordinary directory')
            return (info.st_dev, info.st_ino)
    except FileNotFoundError:
        return None


def create_parent(root: Path, relative: str) -> tuple[int, int]:
    with parent_descriptor(root, relative) as (parent, name):
        os.mkdir(name, mode=0o755, dir_fd=parent)
        info = os.stat(name, dir_fd=parent, follow_symlinks=False)
        os.fsync(parent)
        return (info.st_dev, info.st_ino)


def remove_parent(root: Path, relative: str, identity: tuple[int, int]) -> None:
    with parent_descriptor(root, relative) as (parent, name):
        info = os.stat(name, dir_fd=parent, follow_symlinks=False)
        if not stat.S_ISDIR(info.st_mode) or (info.st_dev, info.st_ino) != identity:
            raise CompareAndSwapError('rollback parent identity changed')
        os.rmdir(name, dir_fd=parent)
        os.fsync(parent)
