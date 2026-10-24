from __future__ import annotations

from dataclasses import dataclass


class SafetyError(RuntimeError):
    """Base class for fail-closed local safety errors."""


class UnsafePathError(SafetyError):
    """Path is outside the owned root or has unsafe metadata."""


class CompareAndSwapError(SafetyError):
    """Expected content did not match the current file."""


class LockError(SafetyError):
    """A lock could not be acquired or used safely."""


class JournalError(SafetyError):
    """A journal record could not be safely persisted or admitted."""


@dataclass(frozen=True)
class WriteResult:
    path: str
    status: str
    sha256: str
    recovery_status: str
    parent_fsync: str


@dataclass(frozen=True)
class LockMetadata:
    lock_id: str
    owner_identity: str
    pid: int
    acquired_at: int


@dataclass(frozen=True)
class JournalRecovery:
    status: str
    operation_id: str | None
    idempotency_key: str | None
    native_ids: tuple[str, ...]
    native_ids_unknown: bool
    reason: str
