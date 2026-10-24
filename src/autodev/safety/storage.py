"""Atomic JSON storage on owned POSIX local roots, with explicit recovery.

This boundary excludes hostile processes changing the owned root concurrently.
Ancestors outside the root (including the host's /tmp alias) are not owned here.
"""
from __future__ import annotations

import fcntl
import json
import os
import stat
import tempfile
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Iterator

from autodev.evidence import sha256_bytes
from autodev.redaction import redact_text
from .types import CompareAndSwapError, UnsafePathError, WriteResult


class SafeStorageError(UnsafePathError):
    pass


class ExpectedHashMismatch(CompareAndSwapError):
    pass


@dataclass(frozen=True)
class RecoveryResult:
    status: str
    value: Any | None
    sha256: str | None
    admissible: bool = False


Checkpoint = Callable[[str, Path], None]
ABSENT = "ABSENT"


def _validate(path: Path, *, directory: bool) -> None:
    try:
        info = path.lstat()
    except OSError:
        raise SafeStorageError("path metadata cannot be inspected") from None
    kind = stat.S_ISDIR if directory else stat.S_ISREG
    if not kind(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o022:
        raise SafeStorageError("unsafe path type, owner, or permissions")


def ensure_private_dir(path: Path) -> None:
    if not path.exists() and not path.is_symlink():
        try:
            path.mkdir(mode=0o700, parents=True, exist_ok=True)
        except OSError:
            raise SafeStorageError("owned directory cannot be established") from None
    _validate(path, directory=True)


def canonical_json_bytes(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
                       allow_nan=False) + "\n").encode("utf-8")


def decode_json(data: bytes) -> Any:
    def object_from_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate JSON key")
            result[key] = value
        return result
    def reject_constant(_value: str) -> None:
        raise ValueError("nonfinite JSON value")
    return json.loads(data, object_pairs_hook=object_from_pairs, parse_constant=reject_constant)


def resolve_under_root(root: Path, relative_path: str | Path, *, target_may_not_exist: bool = True) -> Path:
    root = root.absolute()
    _validate(root, directory=True)
    rel = Path(relative_path)
    if rel.is_absolute() or ".." in rel.parts or not rel.name or rel == Path("."):
        raise SafeStorageError("path must be relative and non-escaping")
    parent = root
    for part in rel.parts[:-1]:
        parent = parent / part
        ensure_private_dir(parent)
    target = parent / rel.name
    if target.exists() or target.is_symlink():
        _validate(target, directory=False)
    elif not target_may_not_exist:
        raise SafeStorageError("target does not exist")
    return target


class SafeStore:
    def __init__(self, root: Path | str) -> None:
        self.root = Path(root).absolute()
        ensure_private_dir(self.root)

    def resolve(self, name: str | Path, *, target_may_not_exist: bool = True) -> Path:
        return resolve_under_root(self.root, name, target_may_not_exist=target_may_not_exist)

    def read_json(self, name: str | Path) -> Any:
        path = self.resolve(name, target_may_not_exist=False)
        try:
            return decode_json(path.read_bytes())
        except (OSError, ValueError):
            raise SafeStorageError("record cannot be safely read") from None

    def current_hash(self, name: str | Path) -> str | None:
        path = self.resolve(name)
        try:
            return sha256_bytes(path.read_bytes()) if path.exists() else None
        except OSError:
            raise SafeStorageError("record cannot be read") from None

    @contextmanager
    def transaction(self, name: str | Path) -> Iterator[None]:
        """Hold the stable per-target inode across read/check/merge/write."""
        path = self.resolve(name)
        identity = sha256_bytes(str(path.relative_to(self.root)).encode())
        lock_path = self.resolve(f".autodev-locks/{identity}.lock")
        try:
            fd = os.open(lock_path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        except OSError:
            raise SafeStorageError("record lock cannot be established") from None
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
            yield
        finally:
            os.close(fd)

    def _recovery_path(self, name: str | Path) -> Path:
        path = self.resolve(name)
        if any(part.startswith(".autodev-") for part in Path(name).parts):
            raise SafeStorageError("storage metadata paths are reserved")
        return self.resolve(path.relative_to(self.root).with_name(f".autodev-{path.name}.write.json"))

    def _replace(self, path: Path, payload: bytes, checkpoint: Checkpoint | None = None) -> None:
        fd, tmp = tempfile.mkstemp(prefix=".autodev-write-", dir=path.parent)
        temporary = Path(tmp)
        try:
            with os.fdopen(fd, "wb") as handle:
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
            if checkpoint:
                checkpoint("file_fsync", path)
                checkpoint("before_replace", path)
            os.replace(temporary, path)
            if checkpoint:
                checkpoint("after_replace", path)
        finally:
            temporary.unlink(missing_ok=True)

    def _fsync_directory(self, directory: Path) -> None:
        fd = os.open(directory, os.O_RDONLY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)

    def _intent(self, path: Path, record: dict[str, Any]) -> None:
        self._replace(path, canonical_json_bytes(record))
        self._fsync_directory(path.parent)

    def write_json_atomic(self, name: str | Path, value: Any, *, expected_hash: str | None = None,
                          expected_sha256: str | None = None, checkpoint: Checkpoint | None = None,
                          owner_identity: str = "safe-store", fail_at: str | None = None,
                          recovery_relative_path: str | Path | None = None) -> WriteResult:
        if recovery_relative_path is not None:
            raise SafeStorageError("custom recovery locations are unsupported")
        with self.transaction(name):
            return self._write_locked(name, value, expected_hash=expected_hash or expected_sha256,
                                      checkpoint=checkpoint, owner_identity=owner_identity, fail_at=fail_at)

    def _write_locked(self, name: str | Path, value: Any, *, expected_hash: str | None = None,
                      checkpoint: Checkpoint | None = None, owner_identity: str = "safe-store",
                      fail_at: str | None = None) -> WriteResult:
        path = self.resolve(name)
        recovery = self.recover(name)
        if recovery.status != "missing" and not recovery.admissible:
            raise SafeStorageError("record requires explicit recovery before writing")
        old = self.current_hash(name)
        if expected_hash is not None and (ABSENT if old is None else old) != expected_hash:
            raise ExpectedHashMismatch("expected content hash did not match current file")
        payload = canonical_json_bytes(value)
        digest = sha256_bytes(payload)
        record = {"schema_version": 1, "old_sha256": old, "new_sha256": digest,
                  "owner_identity": redact_text(owner_identity), "phase": "PREPARED"}
        intent_path = self._recovery_path(name)
        try:
            self._intent(intent_path, record)
        except OSError:
            raise SafeStorageError("write intent durability is uncertain") from None
        if checkpoint:
            checkpoint("before_temp", path)
        if fail_at == "before_temp":
            raise OSError("injected disk failure")

        def observed(label: str, target: Path) -> None:
            if checkpoint:
                checkpoint(label, target)
            if fail_at == label:
                raise OSError("injected disk failure")

        self._replace(path, payload, observed)
        try:
            observed("parent_fsync", path)
            self._fsync_directory(path.parent)
            record["phase"] = "COMMITTED"
            self._intent(intent_path, record)
        except OSError:
            return WriteResult("owned-record", "durability_uncertain", digest, "visible_new_durability_uncertain", "uncertain")
        return WriteResult("owned-record", "written", digest, "visible_new", "synced")

    def recover(self, name: str | Path) -> RecoveryResult:
        try:
            path = self.resolve(name)
            value = self.read_json(name) if path.exists() else None
            digest = self.current_hash(name)
            sidecar = self._recovery_path(name)
            if not sidecar.exists():
                return RecoveryResult("recovered_visible" if path.exists() else "missing", value, digest, True)
            record = decode_json(sidecar.read_bytes())
            if (set(record) != {"schema_version", "old_sha256", "new_sha256", "owner_identity", "phase"}
                    or type(record["schema_version"]) is not int or record["schema_version"] != 1
                    or record["phase"] not in {"PREPARED", "COMMITTED"}
                    or not isinstance(record["owner_identity"], str)
                    or not _digest(record["new_sha256"])
                    or (record["old_sha256"] is not None and not _digest(record["old_sha256"]))):
                raise ValueError
            if digest not in {record["old_sha256"], record["new_sha256"]}:
                raise ValueError
            committed = record["phase"] == "COMMITTED" and digest == record["new_sha256"]
            return RecoveryResult("recovered_visible" if committed else "write_uncertain", value, digest, committed)
        except (OSError, ValueError, TypeError, SafeStorageError):
            return RecoveryResult("corrupt_untrusted", None, None)

    def reconcile_write(self, name: str | Path) -> RecoveryResult:
        """Explicitly sync a known old/new visible record; never repair corruption."""
        with self.transaction(name):
            recovery = self.recover(name)
            if recovery.status == "write_uncertain":
                path = self.resolve(name)
                self._fsync_directory(path.parent)
                record = decode_json(self._recovery_path(name).read_bytes())
                if recovery.sha256 is None:
                    self._recovery_path(name).unlink()
                    self._fsync_directory(path.parent)
                else:
                    record["new_sha256"] = recovery.sha256
                    record["phase"] = "COMMITTED"
                    self._intent(self._recovery_path(name), record)
            return self.recover(name)


def _digest(value: Any) -> bool:
    return isinstance(value, str) and len(value) == 64 and all(c in "0123456789abcdef" for c in value)
