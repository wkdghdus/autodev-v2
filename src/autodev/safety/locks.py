from __future__ import annotations

import fcntl
import json
import os
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from threading import local
from types import TracebackType
from typing import Any, Callable, Iterable, Mapping

from .storage import ExpectedHashMismatch, SafeStore, decode_json, ensure_private_dir
from autodev.evidence import sha256_bytes
from .types import LockError, LockMetadata


class SafeLockError(LockError):
    pass


class LockContention(SafeLockError):
    pass


LOCK_LEVELS = {"installation": 0, "repository": 1, "account": 2}
_LOCK_STACK = local()


@dataclass(frozen=True, order=True)
class LockKey:
    level: str
    identity: str

    def __post_init__(self) -> None:
        if self.level not in LOCK_LEVELS:
            raise SafeLockError("unknown lock level")
        if not self.identity or "/" in self.identity or ".." in Path(self.identity).parts:
            raise SafeLockError("invalid lock identity")

    @property
    def order_key(self) -> tuple[int, str]:
        return (LOCK_LEVELS[self.level], self.identity)


class FileLock:
    def __init__(self, root: Path, level: str, identity: str, *, owner_identity: str) -> None:
        self.key = LockKey(level, identity)
        self.root = root
        self.owner_identity = owner_identity
        self.path = SafeStore(root).resolve(Path("locks") / level / f"{identity}.lock")
        self._handle = None
        self._entered_stack = False

    @property
    def order_key(self) -> tuple[int, str]:
        return self.key.order_key

    def acquire(self, *, blocking: bool = False) -> LockMetadata:
        if self._handle is not None:
            raise SafeLockError("lock is already held by this object")
        stack = _stack()
        if stack and self.order_key < stack[-1]:
            raise SafeLockError("lock acquisition violates installation -> repository -> account order")
        self.path = SafeStore(self.root).resolve(self.path.relative_to(Path(self.root).absolute()))
        fd = os.open(self.path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        self._handle = os.fdopen(fd, "r+", encoding="utf-8")
        try:
            lock_mode = fcntl.LOCK_EX if blocking else fcntl.LOCK_EX | fcntl.LOCK_NB
            fcntl.flock(self._handle.fileno(), lock_mode)
        except OSError:
            self._handle.close()
            self._handle = None
            raise LockContention("kernel lock unavailable; metadata cannot grant ownership") from None
        try:
            previous = self._handle.read()
            if previous:
                prior = decode_json(previous.encode())
                if (set(prior) != {"lock_id", "owner_identity", "pid", "acquired_at", "generation"}
                        or prior["lock_id"] != f"{self.key.level}:{self.key.identity}"
                        or not isinstance(prior["owner_identity"], str)
                        or type(prior["pid"]) is not int or prior["pid"] <= 0
                        or type(prior["acquired_at"]) is not int
                        or not isinstance(prior["generation"], str)):
                    raise SafeLockError("lock owner record requires reconciliation")
            metadata = LockMetadata(f"{self.key.level}:{self.key.identity}", self.owner_identity, os.getpid(), int(time.time()))
            self._handle.seek(0)
            self._handle.truncate()
            json.dump({**metadata.__dict__, "generation": str(uuid.uuid4())}, self._handle, sort_keys=True)
            self._handle.write("\n")
            self._handle.flush()
            os.fsync(self._handle.fileno())
            SafeStore(self.root)._fsync_directory(self.path.parent)
        except Exception:
            self._handle.close()
            self._handle = None
            raise SafeLockError("lock owner record cannot be established") from None
        stack.append(self.order_key)
        self._entered_stack = True
        return metadata

    def release(self) -> None:
        if self._handle is None:
            return
        if self._entered_stack:
            if not _stack() or _stack()[-1] != self.order_key:
                raise SafeLockError("locks must be released in reverse acquisition order")
            _stack().pop()
            self._entered_stack = False
        fcntl.flock(self._handle.fileno(), fcntl.LOCK_UN)
        self._handle.close()
        self._handle = None

    def __enter__(self) -> "FileLock":
        if self._handle is None:
            self.acquire()
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        self.release()


class LockManager:
    def __init__(self, root: Path, *, owner_identity: str = "lock-manager") -> None:
        self.root = root
        self.owner_identity = owner_identity
        ensure_private_dir(self.root)

    def acquire(self, key: LockKey, *, blocking: bool = False) -> FileLock:
        lock = FileLock(self.root, key.level, key.identity, owner_identity=self.owner_identity)
        lock.acquire(blocking=blocking)
        return lock

    def acquire_many(self, keys: Iterable[LockKey], *, blocking: bool = False) -> "OrderedLocks":
        key_tuple = tuple(keys)
        if tuple(sorted(key_tuple, key=lambda item: item.order_key)) != key_tuple:
            raise SafeLockError("locks must be requested in documented canonical order")
        locks = [FileLock(self.root, key.level, key.identity, owner_identity=self.owner_identity) for key in key_tuple]
        manager = OrderedLocks(locks, presorted=True)
        manager.__enter__()
        return manager


class OrderedLocks:
    def __init__(self, locks: Iterable[FileLock], *, presorted: bool = False) -> None:
        raw = tuple(locks)
        ordered = tuple(sorted(raw, key=lambda item: item.order_key))
        if not presorted and tuple(item.order_key for item in raw) != tuple(item.order_key for item in ordered):
            raise SafeLockError("locks must be requested in documented canonical order")
        self.locks = raw if presorted else ordered
        self._entered: list[FileLock] = []

    def __enter__(self) -> "OrderedLocks":
        if self._entered:
            return self
        for lock in self.locks:
            try:
                lock.acquire()
            except Exception:
                for acquired in reversed(self._entered):
                    acquired.release()
                self._entered.clear()
                raise
            self._entered.append(lock)
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        for lock in reversed(self._entered):
            lock.release()
        self._entered.clear()


class SharedJsonMap:
    def __init__(self, store: SafeStore, manager: LockManager) -> None:
        self.store = store
        self.manager = manager

    def update_key(
        self,
        relative_path: str,
        lock_key: LockKey,
        key: str,
        value: Mapping[str, Any],
        *,
        expected_hash: str | None = None,
        checkpoint: Callable[[str], None] | None = None,
    ):
        stable_identity = f"shared-map-{sha256_bytes(Path(relative_path).as_posix().encode('utf-8'))}"
        stable_lock = FileLock(
            self.manager.root,
            lock_key.level,
            stable_identity,
            owner_identity=self.manager.owner_identity,
        )
        stable_lock.acquire(blocking=True)
        try:
            if checkpoint:
                checkpoint("lock")
            with self.store.transaction(relative_path):
                current_hash = self.store.current_hash(relative_path)
                current = self.store.read_json(relative_path) if current_hash is not None else {}
                if checkpoint:
                    checkpoint("read")
                    checkpoint("hash")
                if expected_hash is not None and current_hash != expected_hash:
                    raise ExpectedHashMismatch("shared map preview is stale")
                if not isinstance(current, dict):
                    raise SafeLockError("shared map must be an object")
                merged = dict(current)
                merged[key] = dict(value)
                if checkpoint:
                    checkpoint("merge")
                def observed(label: str, _path: Path) -> None:
                    if checkpoint:
                        checkpoint(label)
                return self.store._write_locked(relative_path, merged, expected_hash=current_hash,
                                                 checkpoint=observed)
        finally:
            stable_lock.release()
            if checkpoint:
                checkpoint("release")


def installation_lock(root: Path, installation_id: str, *, owner_identity: str) -> FileLock:
    return FileLock(root, "installation", installation_id, owner_identity=owner_identity)


def repository_lock(root: Path, repository_id: str, *, owner_identity: str) -> FileLock:
    return FileLock(root, "repository", repository_id, owner_identity=owner_identity)


def account_lock(root: Path, account_id: str, *, owner_identity: str) -> FileLock:
    return FileLock(root, "account", account_id, owner_identity=owner_identity)


def _stack() -> list[tuple[int, str]]:
    stack = getattr(_LOCK_STACK, "value", None)
    if stack is None:
        stack = []
        _LOCK_STACK.value = stack
    return stack
