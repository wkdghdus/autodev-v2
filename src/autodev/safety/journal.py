"""Durable local operation intents. Recovery never authorizes a retry."""
from __future__ import annotations

import json
import time
import uuid
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

from autodev.contracts.errors import ContractError
from autodev.contracts.validators import validate_operation_record
from autodev.evidence import sha256_bytes
from autodev.redaction import redact_text, sanitize
from .storage import SafeStore, canonical_json_bytes, _digest
from .types import JournalError, JournalRecovery, UnsafePathError


UNKNOWN_NATIVE_ID = "native_ids_unknown"


@dataclass(frozen=True)
class OperationRequest:
    operation_kind: str
    installation_id: str
    milestone_id: str | None
    plan_digest: str
    grant_digest: str
    canonical_arguments: Mapping[str, Any]
    idempotency_key: str
    owner_identity: str
    deployment_epoch: int
    local_mutation_target_ids: tuple[str, ...] = ()


def _canonicalize(value: Any) -> Any:
    if isinstance(value, Mapping):
        if any(type(key) is not str for key in value):
            raise JournalError("canonical object keys must be strings")
        return {key: _canonicalize(value[key]) for key in sorted(value)}
    if type(value) in (tuple, list):
        return [_canonicalize(item) for item in value]
    if type(value) in (str, int, bool) or value is None:
        return value
    raise JournalError("unsupported canonical value type")


def _hash(value: Any) -> str:
    return sha256_bytes(canonical_json_bytes(_canonicalize(value)))


def _binding(record: Mapping[str, Any], targets_digest: str) -> dict[str, Any]:
    fields = ("schema_version", "operation_kind", "installation_id", "milestone_id",
              "plan_digest", "grant_digest", "canonical_arguments_digest", "idempotency_key",
              "owner_identity", "deployment_epoch")
    return {**{field: record[field] for field in fields}, "local_targets_digest": targets_digest}


def canonical_request_digest(request: OperationRequest) -> tuple[str, str]:
    if not isinstance(request.canonical_arguments, Mapping):
        raise JournalError("canonical arguments must be an object")
    if type(request.local_mutation_target_ids) is not tuple or any(
            type(item) is not str or not item for item in request.local_mutation_target_ids):
        raise JournalError("local mutation targets must be explicit string identities")
    arguments = _hash(request.canonical_arguments)
    record = _record(request, "validation", arguments, int(time.time()))
    _validate_record(record, ())
    return arguments, _hash(_binding(record, _hash(request.local_mutation_target_ids)))


def _record(request: OperationRequest, operation_id: str, arguments: str, now: int) -> dict[str, Any]:
    return {"schema_version": 1, "operation_id": operation_id,
            "installation_id": request.installation_id, "milestone_id": request.milestone_id,
            "operation_kind": request.operation_kind, "plan_digest": request.plan_digest,
            "grant_digest": request.grant_digest, "canonical_arguments_digest": arguments,
            "idempotency_key": request.idempotency_key, "created_at": now,
            "owner_identity": request.owner_identity, "deployment_epoch": request.deployment_epoch,
            "operation_state": "PREPARED", "native_ids": [],
            "reconciliation_evidence_refs": [], "terminal_result": None}


def _validate_record(record: Any, canaries: tuple[str, ...]) -> None:
    try:
        validate_operation_record(record)
    except (ContractError, TypeError, ValueError):
        raise JournalError("operation record failed validation") from None
    rendered = json.dumps(record, sort_keys=True)
    if sanitize(record, canaries) != record or any(word in rendered.lower() for word in
            ("secret", "token", "password", "api_key", "credential", "authorization", "bearer")):
        raise JournalError("secret-bearing identity fields are forbidden")


class OperationJournal:
    def __init__(self, root: Path, relative_path: str | Path = "journal/operations.json", *,
                 canaries: tuple[str, ...] = ()) -> None:
        self.store = SafeStore(root)
        self.relative_path = relative_path
        self.canaries = canaries

    def _load(self, *, allow_uncertain: bool = False) -> dict[str, Any]:
        recovery = self.store.recover(self.relative_path)
        if recovery.status == "missing":
            return {}
        if recovery.status == "corrupt_untrusted" or (not recovery.admissible and not allow_uncertain):
            raise JournalError("journal storage requires recovery")
        raw = recovery.value
        if (not isinstance(raw, dict) or set(raw) != {"schema_version", "operations"}
                or type(raw["schema_version"]) is not int or raw["schema_version"] != 1
                or not isinstance(raw["operations"], dict)):
            raise JournalError("journal envelope is corrupt")
        ids = set()
        for key, entry in raw["operations"].items():
            if not isinstance(entry, dict) or set(entry) != {
                    "record", "request_digest", "targets_digest", "identity_digest"}:
                raise JournalError("journal entry is corrupt")
            record = entry["record"]
            _validate_record(record, self.canaries)
            if record["idempotency_key"] != key or record["operation_id"] in ids:
                raise JournalError("journal identities conflict")
            ids.add(record["operation_id"])
            if (not _digest(entry["targets_digest"])
                    or entry["request_digest"] != _hash(_binding(record, entry["targets_digest"]))
                    or entry["identity_digest"] != _hash([record["operation_id"], record["created_at"], entry["request_digest"]])):
                raise JournalError("journal identity binding is corrupt")
        return raw["operations"]

    def _save(self, operations: dict[str, Any]) -> None:
        try:
            result = self.store._write_locked(self.relative_path, {"schema_version": 1, "operations": operations},
                                             expected_hash=self.store.current_hash(self.relative_path),
                                             owner_identity="operation-journal")
        except (OSError, UnsafePathError):
            raise JournalError("journal write failed; reconciliation required") from None
        if result.status != "written":
            raise JournalError("journal durability is uncertain")

    def _prepare(self, request: OperationRequest, operation_id: str | None, now: int | None,
                 *, fresh: bool) -> dict[str, Any]:
        arguments, request_digest = canonical_request_digest(request)
        operations = self._load()
        existing = operations.get(request.idempotency_key)
        if existing is not None:
            if (existing["request_digest"] != request_digest or
                    (operation_id is not None and existing["record"]["operation_id"] != operation_id)):
                raise JournalError("idempotency identity is already bound to a different request")
            if fresh:
                raise JournalError("existing operation requires reconciliation before retry")
            return dict(existing["record"])
        record = _record(request, str(uuid.uuid4()) if operation_id is None else operation_id,
                         arguments, int(time.time()) if now is None else now)
        _validate_record(record, self.canaries)
        if any(entry["record"]["operation_id"] == record["operation_id"] for entry in operations.values()):
            raise JournalError("operation identity is already bound")
        operations[request.idempotency_key] = {
            "record": record, "request_digest": request_digest,
            "targets_digest": _hash(request.local_mutation_target_ids),
            "identity_digest": _hash([record["operation_id"], record["created_at"], request_digest])}
        self._save(operations)
        return dict(record)

    def prepare(self, request: OperationRequest, *, operation_id: str | None = None,
                now: int | None = None) -> Mapping[str, Any]:
        with self.store.transaction(self.relative_path):
            return self._prepare(request, operation_id, now, fresh=False)

    def _transition(self, key: str, before: str, after: str, **changes: Any) -> Mapping[str, Any]:
        with self.store.transaction(self.relative_path):
            operations = self._load()
            entry = operations.get(key)
            if entry is None or entry["record"]["operation_state"] != before:
                raise JournalError("operation transition requires reconciliation")
            record = {**entry["record"], **changes, "operation_state": after}
            _validate_record(record, self.canaries)
            entry["record"] = record
            self._save(operations)
            return dict(record)

    def mark_sent(self, idempotency_key: str, *, native_ids: tuple[str, ...] = ()) -> Mapping[str, Any]:
        return self._transition(idempotency_key, "PREPARED", "SENT",
                                native_ids=list(native_ids),
                                reconciliation_evidence_refs=[] if native_ids else [UNKNOWN_NATIVE_ID])

    def acknowledge(self, idempotency_key: str, *, terminal_result: str = "SUCCEEDED") -> Mapping[str, Any]:
        if terminal_result not in {"SUCCEEDED", "FAILED"}:
            raise JournalError("unsupported terminal result")
        return self._transition(idempotency_key, "SENT", "ACKNOWLEDGED", terminal_result=terminal_result)

    def recover(self, idempotency_key: str) -> JournalRecovery:
        key = redact_text(idempotency_key, self.canaries)
        with self.store.transaction(self.relative_path):
            recovery = self.store.recover(self.relative_path)
            try:
                operations = self._load(allow_uncertain=True)
            except JournalError:
                # These are sanitized, untrusted diagnostic hints, never authority.
                op = None
                raw = recovery.value
                if raw is None:
                    try:
                        raw = self.store.read_json(self.relative_path)
                    except (OSError, ValueError, UnsafePathError):
                        raw = None
                if isinstance(raw, dict) and isinstance(raw.get("operations"), dict):
                    entry = raw["operations"].get(idempotency_key)
                    if isinstance(entry, dict) and isinstance(entry.get("record"), dict):
                        hint = entry["record"].get("operation_id")
                        if isinstance(hint, str):
                            op = redact_text(hint, self.canaries)
                return JournalRecovery("CORRUPT", op, key, (), True, "untrusted journal identity hints")
            entry = operations.get(idempotency_key)
            if entry is None:
                return JournalRecovery("MISSING", None, key, (), True, "no operation record")
            record = entry["record"]
            state = record["operation_state"]
            native = tuple(record["native_ids"])
            uncertain = not recovery.admissible or state in {"PREPARED", "SENT", "UNCERTAIN"}
            return JournalRecovery("UNCERTAIN" if uncertain else state, record["operation_id"], key,
                                   native, not native or UNKNOWN_NATIVE_ID in native,
                                   "reconciliation required" if uncertain else "acknowledged")

    def run_with_journal(self, request: OperationRequest, callback: Callable[[], Any], *,
                         native_ids_before_effect: tuple[str, ...] = (), fail_ack_write: bool = False,
                         checkpoint: Callable[[str], None] | None = None) -> Any:
        with self.store.transaction(self.relative_path):
            self._prepare(request, None, None, fresh=True)
        if checkpoint:
            checkpoint("PREPARED")
        self.mark_sent(request.idempotency_key, native_ids=native_ids_before_effect)
        if checkpoint:
            checkpoint("SENT")
        result = callback()
        if checkpoint:
            checkpoint("EFFECT")
        if fail_ack_write:
            raise JournalError("acknowledgement write failed after effect")
        self.acknowledge(request.idempotency_key)
        return result


