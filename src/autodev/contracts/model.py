from __future__ import annotations

from dataclasses import dataclass
from types import MappingProxyType
from typing import Any, Mapping


JsonValue = str | int | bool | None | tuple["JsonValue", ...] | Mapping[str, "JsonValue"]


def freeze(value: Any) -> Any:
    if isinstance(value, Mapping):
        return MappingProxyType({str(key): freeze(item) for key, item in value.items()})
    if isinstance(value, list | tuple):
        return tuple(freeze(item) for item in value)
    return value


def unfrozen(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {key: unfrozen(item) for key, item in value.items()}
    if isinstance(value, tuple):
        return [unfrozen(item) for item in value]
    return value


@dataclass(frozen=True)
class CommandSpec:
    id: str
    argv: tuple[str, ...]
    cwd: str
    input_paths: tuple[str, ...]
    network_policy: str
    timeout_seconds: int
    approval_binding: str | None = None


@dataclass(frozen=True)
class ProjectContract:
    schema_version: int
    setup_state: str
    project_id: str
    slug: str
    name: str
    sources: Mapping[str, Any]
    execution: Mapping[str, Any]
    verification_commands: tuple[CommandSpec, ...]
    acceptance_sources: tuple[str, ...]
    require_independent_review: bool
    requested_authority: Mapping[str, str]
    raw: Mapping[str, Any]

    def __post_init__(self) -> None:
        object.__setattr__(self, "sources", freeze(self.sources))
        object.__setattr__(self, "execution", freeze(self.execution))
        object.__setattr__(self, "requested_authority", freeze(self.requested_authority))
        object.__setattr__(self, "raw", freeze(self.raw))


@dataclass(frozen=True)
class ExecutionMilestone:
    id: str
    title: str
    depends_on: tuple[str, ...]
    authority_refs: tuple[Mapping[str, Any], ...]
    acceptance_refs: tuple[str, ...]
    scope: Mapping[str, Any]
    verification_ids: tuple[str, ...]
    approval: Mapping[str, Any]
    base_policy: str
    evidence_refs: tuple[str, ...]

    def __post_init__(self) -> None:
        object.__setattr__(self, "depends_on", tuple(self.depends_on))
        object.__setattr__(self, "authority_refs", tuple(freeze(item) for item in self.authority_refs))
        object.__setattr__(self, "acceptance_refs", tuple(self.acceptance_refs))
        object.__setattr__(self, "scope", freeze(self.scope))
        object.__setattr__(self, "verification_ids", tuple(self.verification_ids))
        object.__setattr__(self, "approval", freeze(self.approval))
        object.__setattr__(self, "evidence_refs", tuple(self.evidence_refs))


@dataclass(frozen=True)
class ExecutionIndex:
    schema_version: int
    project_id: str
    milestones: tuple[ExecutionMilestone, ...]
    raw: Mapping[str, Any]

    def __post_init__(self) -> None:
        object.__setattr__(self, "milestones", tuple(self.milestones))
        object.__setattr__(self, "raw", freeze(self.raw))


@dataclass(frozen=True)
class MetadataSnapshot:
    repo_realpath: str
    git_common_dir_realpath: str
    project_id: str | None = None
    installation_id: str | None = None
    slug_registry: Mapping[str, str] = MappingProxyType({})
    symlink_paths: tuple[str, ...] = ()
    casefold_paths: tuple[str, ...] = ()
    revision: str | None = None
    dirty_fingerprint: str | None = None
    profile_identity: str | None = None
    process_generation: str | None = None


@dataclass(frozen=True)
class InstallationBinding:
    schema_version: int
    installation_id: str
    project_id: str
    repo_realpath: str
    git_common_dir_realpath: str
    profile_identity: str
    process_generation: str
    deployment_epoch: int
    slug: str | None = None
    raw: Mapping[str, Any] = MappingProxyType({})


@dataclass(frozen=True)
class ValidationReceipt:
    schema_version: int
    gate_id: str
    evidence_class: str
    probe_id: str
    result: str
    installation_id: str
    project_id: str
    invocation_source: str
    profile_identity: str
    process_generation: str
    observed_at: int
    expires_at: int
    capability_fingerprint: str
    repo_revision: str
    dirty_fingerprint: str
    relevant_hashes: Mapping[str, str]
    redacted_route_identity: str
    allowed_effects: tuple[str, ...]
    observed_effects: tuple[str, ...]
    cleanup_state: str
    native_trace_refs: tuple[str, ...]
    invalidation_keys: tuple[str, ...]
    raw: Mapping[str, Any] = MappingProxyType({})

    def __post_init__(self) -> None:
        object.__setattr__(self, "relevant_hashes", freeze(self.relevant_hashes))
        object.__setattr__(self, "allowed_effects", tuple(self.allowed_effects))
        object.__setattr__(self, "observed_effects", tuple(self.observed_effects))
        object.__setattr__(self, "native_trace_refs", tuple(self.native_trace_refs))
        object.__setattr__(self, "invalidation_keys", tuple(self.invalidation_keys))
        object.__setattr__(self, "raw", freeze(self.raw))


@dataclass(frozen=True)
class MutationGrant:
    schema_version: int
    grant_id: str
    operator_identity: str
    installation_id: str
    project_id: str
    repository_membership_rule: str
    protected_refs: tuple[str, ...]
    operation_classes: tuple[str, ...]
    permission_scope: Mapping[str, str]
    approved_product_artifact_hashes: Mapping[str, str]
    resource_constraints: Mapping[str, Any]
    deployment_epoch: int
    expires_at: int
    revoked_at: int | None
    meaningful_impact: str
    native_limit: str | None
    enforcement_limit: str | None
    raw: Mapping[str, Any] = MappingProxyType({})

    def __post_init__(self) -> None:
        object.__setattr__(self, "protected_refs", tuple(self.protected_refs))
        object.__setattr__(self, "operation_classes", tuple(self.operation_classes))
        object.__setattr__(self, "permission_scope", freeze(self.permission_scope))
        object.__setattr__(self, "approved_product_artifact_hashes", freeze(self.approved_product_artifact_hashes))
        object.__setattr__(self, "resource_constraints", freeze(self.resource_constraints))
        object.__setattr__(self, "raw", freeze(self.raw))


@dataclass(frozen=True)
class ApprovalReceipt:
    schema_version: int
    receipt_id: str
    operator_identity: str
    installation_id: str
    project_id: str
    content_hashes: Mapping[str, str]
    permission_scope: Mapping[str, str]
    deployment_epoch: int
    expires_at: int
    revoked_at: int | None
    native_limit: str | None
    enforcement_limit: str | None
    scope: Mapping[str, Any] = MappingProxyType({})
    raw: Mapping[str, Any] = MappingProxyType({})

    def __post_init__(self) -> None:
        object.__setattr__(self, "content_hashes", freeze(self.content_hashes))
        object.__setattr__(self, "permission_scope", freeze(self.permission_scope))
        object.__setattr__(self, "scope", freeze(self.scope))
        object.__setattr__(self, "raw", freeze(self.raw))


@dataclass(frozen=True)
class OperationJournalRecord:
    schema_version: int
    operation_id: str
    installation_id: str
    milestone_id: str | None
    operation_kind: str
    plan_digest: str
    grant_digest: str
    canonical_arguments_digest: str
    idempotency_key: str
    created_at: int
    owner_identity: str
    deployment_epoch: int
    operation_state: str
    native_ids: tuple[str, ...]
    reconciliation_evidence_refs: tuple[str, ...]
    terminal_result: str | None
    raw: Mapping[str, Any] = MappingProxyType({})

    def __post_init__(self) -> None:
        object.__setattr__(self, "native_ids", tuple(self.native_ids))
        object.__setattr__(self, "reconciliation_evidence_refs", tuple(self.reconciliation_evidence_refs))
        object.__setattr__(self, "raw", freeze(self.raw))


@dataclass(frozen=True)
class CommandResult:
    schema_version: int
    operation: Mapping[str, Any]
    outcome: str
    checks: tuple[Mapping[str, Any], ...]
    warnings: tuple[str, ...]
    planned_changes: tuple[Mapping[str, Any], ...]
    applied_changes: tuple[Mapping[str, Any], ...]
    next_safe_action: str
    raw: Mapping[str, Any]

    def __post_init__(self) -> None:
        object.__setattr__(self, "operation", freeze(self.operation))
        object.__setattr__(self, "checks", tuple(freeze(item) for item in self.checks))
        object.__setattr__(self, "warnings", tuple(self.warnings))
        object.__setattr__(self, "planned_changes", tuple(freeze(item) for item in self.planned_changes))
        object.__setattr__(self, "applied_changes", tuple(freeze(item) for item in self.applied_changes))
        object.__setattr__(self, "raw", freeze(self.raw))


@dataclass(frozen=True)
class UnsupportedChangePlan:
    schema_version: int
    kind: str
    plan_id: str
    reason: str = "UNSUPPORTED"
    raw: Mapping[str, Any] = MappingProxyType({})


@dataclass(frozen=True)
class MigrationPreview:
    schema_version: int
    source_sha256: str
    legacy_fields: tuple[Mapping[str, str], ...]
    draft_target: Mapping[str, Any]
    unresolved_fields: tuple[str, ...]
    applicable: bool = False
    writes_performed: bool = False

    @property
    def field_inventory(self) -> tuple[str, ...]:
        return tuple(field["path"] for field in self.legacy_fields)

    @property
    def draft(self) -> Mapping[str, Any]:
        return self.draft_target

    def __post_init__(self) -> None:
        object.__setattr__(self, "legacy_fields", tuple(freeze(item) for item in self.legacy_fields))
        object.__setattr__(self, "draft_target", freeze(self.draft_target))
        object.__setattr__(self, "unresolved_fields", tuple(self.unresolved_fields))


@dataclass(frozen=True)
class ExecutionEligibility:
    eligible_ids: tuple[str, ...]
    reason_codes: Mapping[str, tuple[str, ...]]

    def __post_init__(self) -> None:
        object.__setattr__(self, "eligible_ids", tuple(self.eligible_ids))
        object.__setattr__(
            self,
            "reason_codes",
            MappingProxyType({key: tuple(value) for key, value in self.reason_codes.items()}),
        )
