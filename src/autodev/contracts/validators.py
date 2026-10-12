from __future__ import annotations

import hashlib
import re
from collections.abc import Mapping
from typing import Any

from .errors import ContractError, fail, issue
from .model import (
    ApprovalReceipt,
    CommandResult,
    CommandSpec,
    ExecutionEligibility,
    ExecutionIndex,
    ExecutionMilestone,
    InstallationBinding,
    MetadataSnapshot,
    MigrationPreview,
    MutationGrant,
    OperationJournalRecord,
    ProjectContract,
    UnsupportedChangePlan,
    ValidationReceipt,
    freeze,
)
from .yaml_subset import line_for, parse_yaml_subset, reject_unknowns, require_mapping


UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
SLUG_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,62}$")
HEX256_RE = re.compile(r"^[0-9a-f]{64}$")
PERMISSIONS = {"denied", "human", "autonomous"}
PROJECT_FIELDS = {
    "schema_version",
    "setup_state",
    "project",
    "sources",
    "execution",
    "verification",
    "authority",
}
EXECUTION_FIELDS = {"schema_version", "project_id", "milestones"}


def load_project_yaml(data: bytes | str, metadata: MetadataSnapshot | None = None) -> ProjectContract:
    return validate_project(parse_yaml_subset(data, source_name="PROJECT.yaml"), metadata)


def load_execution_yaml(data: bytes | str, project: ProjectContract) -> ExecutionIndex:
    return validate_execution(parse_yaml_subset(data, source_name="EXECUTION.yaml"), project)


def validate_project(raw_value: Any, metadata: MetadataSnapshot | None = None) -> ProjectContract:
    raw = require_mapping(raw_value, "PROJECT")
    reject_unknowns(raw, PROJECT_FIELDS, "PROJECT")
    if raw.get("schema_version") != 2:
        fail("schema_version", "unsupported_version", "PROJECT schema_version must be 2", line_for(raw, "schema_version"))
    setup_state = _enum(raw.get("setup_state"), "setup_state", {"draft", "configured"})
    project = _mapping(raw.get("project"), "project", {"id", "slug", "name"})
    project_id = _uuid(project.get("id"), "project.id")
    slug = _slug(project.get("slug"), "project.slug")
    if metadata and metadata.slug_registry.get(slug) not in {None, project_id}:
        fail("project.slug", "slug_collision", "slug is bound to a different project")
    name = _string(project.get("name"), "project.name", nonempty=True)

    sources = _mapping(raw.get("sources"), "sources", {"requirements", "context", "discovery", "execution_index"})
    discovery = _mapping(sources.get("discovery"), "sources.discovery", {"roots"})
    for field in ("requirements", "context"):
        _paths(sources.get(field), f"sources.{field}", metadata, allow_empty=setup_state == "draft")
    _paths(discovery.get("roots"), "sources.discovery.roots", metadata, allow_empty=setup_state == "draft")
    _path(sources.get("execution_index"), "sources.execution_index", metadata)

    execution = _mapping(
        raw.get("execution"),
        "execution",
        {
            "harness",
            "workflow",
            "base_policy",
            "target_ref",
            "max_active_milestones",
            "max_primary_actions_per_cycle",
        },
    )
    _const(execution.get("harness"), "execution.harness", "gajae")
    _const(execution.get("workflow"), "execution.workflow", "approved_roadmap_only")
    _const(execution.get("base_policy"), "execution.base_policy", "dependencies_integrated")
    if setup_state == "configured":
        _string(execution.get("target_ref"), "execution.target_ref", nonempty=True)
    elif execution.get("target_ref") is not None:
        _string(execution.get("target_ref"), "execution.target_ref", nonempty=True)
    _const(execution.get("max_active_milestones"), "execution.max_active_milestones", 1)
    _const(execution.get("max_primary_actions_per_cycle"), "execution.max_primary_actions_per_cycle", 1)

    verification = _mapping(
        raw.get("verification"),
        "verification",
        {"commands", "acceptance_sources", "require_independent_review"},
    )
    commands = tuple(_command(item, index, metadata) for index, item in enumerate(_list(verification.get("commands"), "verification.commands")))
    if setup_state == "configured" and not commands:
        fail("verification.commands", "missing_required", "configured PROJECT requires verification commands")
    acceptance_sources = tuple(
        _path(item, f"verification.acceptance_sources[{index}]", metadata)
        for index, item in enumerate(_list(verification.get("acceptance_sources"), "verification.acceptance_sources"))
    )
    _const(verification.get("require_independent_review"), "verification.require_independent_review", True)
    authority = _mapping(raw.get("authority"), "authority", {"requested"})
    requested = _mapping_any(authority.get("requested"), "authority.requested")
    for key, value in requested.items():
        if value not in PERMISSIONS:
            fail(f"authority.requested.{key}", "invalid_permission", "permission must be denied, human, or autonomous")

    if setup_state == "configured":
        for field, items in (
            ("sources.requirements", sources.get("requirements")),
            ("sources.context", sources.get("context")),
            ("sources.discovery.roots", discovery.get("roots")),
            ("verification.acceptance_sources", verification.get("acceptance_sources")),
        ):
            if not items:
                fail(field, "missing_required", "configured PROJECT requires explicit values")

    return ProjectContract(
        schema_version=2,
        setup_state=setup_state,
        project_id=project_id,
        slug=slug,
        name=name,
        sources=freeze(sources),
        execution=freeze(execution),
        verification_commands=commands,
        acceptance_sources=acceptance_sources,
        require_independent_review=True,
        requested_authority=freeze(requested),
        raw=freeze(raw),
    )


def validate_execution(raw_value: Any, project: ProjectContract) -> ExecutionIndex:
    raw = require_mapping(raw_value, "EXECUTION")
    reject_unknowns(raw, EXECUTION_FIELDS, "EXECUTION")
    if raw.get("schema_version") != 2:
        fail("schema_version", "unsupported_version", "EXECUTION schema_version must be 2")
    project_id = _uuid(raw.get("project_id"), "project_id")
    if project_id != project.project_id:
        fail("project_id", "project_mismatch", "EXECUTION project_id must match PROJECT")
    verification_ids = {command.id for command in project.verification_commands}
    milestone_values = _list(raw.get("milestones"), "milestones")
    ids: set[str] = set()
    milestones: list[ExecutionMilestone] = []
    for index, item in enumerate(milestone_values):
        field = f"milestones[{index}]"
        milestone = _mapping(
            item,
            field,
            {
                "id",
                "title",
                "depends_on",
                "authority_refs",
                "acceptance_refs",
                "scope",
                "verification_ids",
                "approval",
                "base_policy",
                "evidence_refs",
            },
        )
        mid = _string(milestone.get("id"), f"{field}.id", nonempty=True)
        if mid in ids:
            fail(f"{field}.id", "duplicate_id", "duplicate milestone id")
        ids.add(mid)
        scope = _mapping(milestone.get("scope"), f"{field}.scope", {"allowed_paths", "exclusions", "prohibited_operations"})
        for path_index, path_text in enumerate(_list(scope.get("allowed_paths"), f"{field}.scope.allowed_paths")):
            _path(path_text, f"{field}.scope.allowed_paths[{path_index}]", None)
        depends_on = tuple(_string(dep, f"{field}.depends_on[]", nonempty=True) for dep in _list(milestone.get("depends_on"), f"{field}.depends_on"))
        refs = tuple(_content_ref(ref, f"{field}.authority_refs[{ref_index}]") for ref_index, ref in enumerate(_list(milestone.get("authority_refs"), f"{field}.authority_refs")))
        acceptance = tuple(_content_ref(ref, f"{field}.acceptance_refs[{ref_index}]") for ref_index, ref in enumerate(_list(milestone.get("acceptance_refs"), f"{field}.acceptance_refs")))
        vids = tuple(_string(vid, f"{field}.verification_ids[]", nonempty=True) for vid in _list(milestone.get("verification_ids"), f"{field}.verification_ids"))
        for vid in vids:
            if vid not in verification_ids:
                fail(f"{field}.verification_ids", "unknown_verification_id", "verification id is not defined by PROJECT")
        approval = _mapping(milestone.get("approval"), f"{field}.approval", {"state", "receipt_ref"})
        _enum(approval.get("state"), f"{field}.approval.state", {"proposed", "approved", "revoked"})
        milestones.append(
            ExecutionMilestone(
                id=mid,
                title=_string(milestone.get("title"), f"{field}.title", nonempty=True),
                depends_on=depends_on,
                authority_refs=refs,
                acceptance_refs=acceptance,
                scope=freeze(scope),
                verification_ids=vids,
                approval=freeze(approval),
                base_policy=_const(milestone.get("base_policy"), f"{field}.base_policy", "dependencies_integrated"),
                evidence_refs=tuple(
                    _string(ref, f"{field}.evidence_refs[]", nonempty=True)
                    for ref in _list(milestone.get("evidence_refs"), f"{field}.evidence_refs")
                ),
            )
        )
    for milestone in milestones:
        for dep in milestone.depends_on:
            if dep not in ids:
                fail(f"milestones.{milestone.id}.depends_on", "missing_dependency", "dependency id is not defined")
    _reject_cycles(milestones)
    return ExecutionIndex(schema_version=2, project_id=project_id, milestones=tuple(milestones), raw=freeze(raw))


def evaluate_execution_eligibility(index: ExecutionIndex, current_digests: Mapping[str, str]) -> ExecutionEligibility:
    by_id = {milestone.id: milestone for milestone in index.milestones}
    eligible: list[str] = []
    reasons: dict[str, tuple[str, ...]] = {}
    for milestone in index.milestones:
        item_reasons: list[str] = []
        if milestone.approval.get("state") != "approved":
            item_reasons.append("APPROVAL_NOT_APPROVED")
        if not milestone.approval.get("receipt_ref"):
            item_reasons.append("APPROVAL_RECEIPT_MISSING")
        if not milestone.scope.get("allowed_paths"):
            item_reasons.append("SCOPE_MISSING")
        if not milestone.verification_ids:
            item_reasons.append("VERIFICATION_MISSING")
        for dep in milestone.depends_on:
            if dep not in by_id:
                item_reasons.append("DEPENDENCY_MISSING")
        for ref in (*milestone.authority_refs, *milestone.acceptance_refs):
            if current_digests.get(ref["path"]) != ref["digest"]:
                item_reasons.append("CONTENT_DIGEST_STALE")
        if item_reasons:
            reasons[milestone.id] = tuple(dict.fromkeys(item_reasons))
        else:
            eligible.append(milestone.id)
            reasons[milestone.id] = ()
    return ExecutionEligibility(tuple(eligible), reasons)


def validate_installation_binding(raw_value: Any) -> InstallationBinding:
    raw = _mapping(
        raw_value,
        "installation",
        {
            "schema_version",
            "installation_id",
            "project_id",
            "repo_realpath",
            "git_common_dir_realpath",
            "profile_identity",
            "service_identity",
            "root_binding_policy",
            "runtime_capability_manifest_ref",
            "model_routes",
            "auth_account_refs",
            "resource_policy",
            "deployment_grant_ref",
            "skill_hash",
            "delivery_target_ref",
            "cron_id",
            "cron_ownership",
            "desired_enabled",
            "deployment_epoch",
            "project_slug",
        },
        optional={"project_slug"},
    )
    _schema(raw, "installation", expected=1)
    _reject_secret_values(raw, "installation")
    _string(raw.get("service_identity"), "service_identity", nonempty=True)
    _string(raw.get("root_binding_policy"), "root_binding_policy", nonempty=True)
    _string(raw.get("runtime_capability_manifest_ref"), "runtime_capability_manifest_ref", nonempty=True)
    _mapping_any(raw.get("model_routes"), "model_routes")
    for route in _list(raw.get("auth_account_refs"), "auth_account_refs"):
        _string(route, "auth_account_refs[]", nonempty=True)
    _mapping_any(raw.get("resource_policy"), "resource_policy")
    _string(raw.get("deployment_grant_ref"), "deployment_grant_ref", nonempty=True)
    _hash(raw.get("skill_hash"), "skill_hash")
    _string(raw.get("delivery_target_ref"), "delivery_target_ref", nonempty=True)
    _optional_string(raw.get("cron_id"), "cron_id")
    _string(raw.get("cron_ownership"), "cron_ownership", nonempty=True)
    _bool(raw.get("desired_enabled"), "desired_enabled")
    return InstallationBinding(
        schema_version=1,
        installation_id=_uuid(raw.get("installation_id"), "installation_id"),
        project_id=_uuid(raw.get("project_id"), "project_id"),
        repo_realpath=_absolute(raw.get("repo_realpath"), "repo_realpath"),
        git_common_dir_realpath=_absolute(raw.get("git_common_dir_realpath"), "git_common_dir_realpath"),
        profile_identity=_string(raw.get("profile_identity"), "profile_identity", nonempty=True),
        process_generation=_string(raw.get("process_generation") or "UNKNOWN", "process_generation", nonempty=True),
        deployment_epoch=_positive_int(raw.get("deployment_epoch"), "deployment_epoch"),
        slug=None if raw.get("project_slug") is None else _slug(raw.get("project_slug"), "project_slug"),
        raw=freeze(raw),
    )


def validate_validation_receipt(raw_value: Any) -> ValidationReceipt:
    raw = _mapping(
        raw_value,
        "validation_receipt",
        {
            "schema_version",
            "gate_id",
            "evidence_class",
            "probe_id",
            "result",
            "installation_id",
            "project_id",
            "invocation_source",
            "profile_identity",
            "process_generation",
            "observed_at",
            "expires_at",
            "capability_fingerprint",
            "repo_revision",
            "dirty_input_fingerprint",
            "bound_hashes",
            "route_identity",
            "allowed_effects",
            "observed_effects",
            "cleanup_state",
            "native_trace_refs",
            "invalidation_keys",
        },
    )
    _schema(raw, "validation_receipt", expected=1)
    evidence_class = _enum(raw.get("evidence_class"), "evidence_class", {"SIMULATED", "LIVE"})
    result = _enum(raw.get("result"), "result", {"PASS", "FAIL", "UNKNOWN", "NOT_RUN", "BLOCKED_EXTERNAL"})
    native_refs = tuple(_string(ref, "native_trace_refs[]", nonempty=True) for ref in _list(raw.get("native_trace_refs"), "native_trace_refs"))
    if evidence_class == "LIVE" and result == "PASS" and not native_refs:
        fail("native_trace_refs", "missing_native_trace", "LIVE PASS requires native trace references")
    return ValidationReceipt(
        schema_version=1,
        gate_id=_string(raw.get("gate_id"), "gate_id", nonempty=True),
        evidence_class=evidence_class,
        probe_id=_string(raw.get("probe_id"), "probe_id", nonempty=True),
        result=result,
        installation_id=_uuid(raw.get("installation_id"), "installation_id"),
        project_id=_uuid(raw.get("project_id"), "project_id"),
        invocation_source=_string(raw.get("invocation_source"), "invocation_source", nonempty=True),
        profile_identity=_string(raw.get("profile_identity"), "profile_identity", nonempty=True),
        process_generation=_string(raw.get("process_generation"), "process_generation", nonempty=True),
        observed_at=_positive_int(raw.get("observed_at"), "observed_at"),
        expires_at=_positive_int(raw.get("expires_at"), "expires_at"),
        capability_fingerprint=_hash(raw.get("capability_fingerprint"), "capability_fingerprint"),
        repo_revision=_string(raw.get("repo_revision"), "repo_revision", nonempty=True),
        dirty_fingerprint=_hash(raw.get("dirty_input_fingerprint"), "dirty_input_fingerprint"),
        relevant_hashes=_hash_map(raw.get("bound_hashes"), "bound_hashes"),
        redacted_route_identity=_string(raw.get("route_identity"), "route_identity", nonempty=True),
        allowed_effects=tuple(_string(x, "allowed_effects[]", nonempty=True) for x in _list(raw.get("allowed_effects"), "allowed_effects")),
        observed_effects=tuple(_string(x, "observed_effects[]", nonempty=True) for x in _list(raw.get("observed_effects"), "observed_effects")),
        cleanup_state=_enum(raw.get("cleanup_state"), "cleanup_state", {"COMPLETE", "INCOMPLETE", "UNKNOWN"}),
        native_trace_refs=native_refs,
        invalidation_keys=tuple(_string(x, "invalidation_keys[]", nonempty=True) for x in _list(raw.get("invalidation_keys"), "invalidation_keys")),
        raw=freeze(raw),
    )


def validate_mutation_grant(raw_value: Any) -> MutationGrant:
    raw = _mapping(
        raw_value,
        "mutation_grant",
        {
            "schema_version",
            "grant_id",
            "operator_identity",
            "operator_action",
            "installation_id",
            "project_id",
            "operation_classes",
            "repository_membership_rule",
            "managed_worktree_membership_rule",
            "protected_files",
            "protected_refs",
            "allowed_routes",
            "artifact_hashes",
            "resource_constraints",
            "issued_at",
            "expires_at",
            "revocation_epoch",
            "deployment_epoch",
            "enforcement_backend",
            "content_digest",
        },
    )
    _schema(raw, "mutation_grant", expected=1)
    _reject_secret_values(raw, "mutation_grant")
    _string(raw.get("managed_worktree_membership_rule"), "managed_worktree_membership_rule", nonempty=True)
    for item in _list(raw.get("protected_files"), "protected_files"):
        _string(item, "protected_files[]", nonempty=True)
    for item in _list(raw.get("allowed_routes"), "allowed_routes"):
        _string(item, "allowed_routes[]", nonempty=True)
    _positive_int(raw.get("issued_at"), "issued_at")
    _hash(raw.get("content_digest"), "content_digest")
    artifact_hashes = _hash_map(raw.get("artifact_hashes"), "artifact_hashes")
    if not artifact_hashes:
        fail("artifact_hashes", "missing_required", "artifact_hashes must not be empty")
    return MutationGrant(
        schema_version=1,
        grant_id=_string(raw.get("grant_id"), "grant_id", nonempty=True),
        operator_identity=_string(raw.get("operator_identity"), "operator_identity", nonempty=True),
        installation_id=_uuid(raw.get("installation_id"), "installation_id"),
        project_id=_uuid(raw.get("project_id"), "project_id"),
        repository_membership_rule=_string(raw.get("repository_membership_rule"), "repository_membership_rule", nonempty=True),
        protected_refs=tuple(_string(x, "protected_refs[]", nonempty=True) for x in _list(raw.get("protected_refs"), "protected_refs")),
        operation_classes=tuple(_string(x, "operation_classes[]", nonempty=True) for x in _list(raw.get("operation_classes"), "operation_classes")),
        permission_scope=freeze({name: "human" for name in _list(raw.get("operation_classes"), "operation_classes")}),
        approved_product_artifact_hashes=artifact_hashes,
        resource_constraints=freeze(_mapping_any(raw.get("resource_constraints"), "resource_constraints")),
        deployment_epoch=_positive_int(raw.get("deployment_epoch"), "deployment_epoch"),
        expires_at=_positive_int(raw.get("expires_at"), "expires_at"),
        revoked_at=_positive_int(raw.get("revocation_epoch"), "revocation_epoch"),
        meaningful_impact=_string(raw.get("operator_action"), "operator_action", nonempty=True),
        native_limit=_string(raw.get("enforcement_backend"), "enforcement_backend", nonempty=True),
        enforcement_limit=_string(raw.get("enforcement_backend"), "enforcement_backend", nonempty=True),
        raw=freeze(raw),
    )


def validate_approval_receipt(raw_value: Any) -> ApprovalReceipt:
    raw = _mapping(
        raw_value,
        "approval_receipt",
        {
            "schema_version",
            "receipt_id",
            "operator_identity",
            "operator_action",
            "project_id",
            "installation_id",
            "artifact_digests",
            "operation_classes",
            "scope",
            "issued_at",
            "expires_at",
            "revocation_epoch",
            "deployment_epoch",
            "content_digest",
        },
    )
    _schema(raw, "approval_receipt", expected=1)
    _reject_secret_values(raw, "approval_receipt")
    _mapping_any(raw.get("scope"), "scope")
    _positive_int(raw.get("issued_at"), "issued_at")
    _hash(raw.get("content_digest"), "content_digest")
    content_hashes = _hash_map(raw.get("artifact_digests"), "artifact_digests")
    if not content_hashes:
        fail("artifact_digests", "missing_required", "artifact_digests must not be empty")
    operation_classes = _list(raw.get("operation_classes"), "operation_classes")
    if not operation_classes:
        fail("operation_classes", "missing_required", "operation_classes must not be empty")
    return ApprovalReceipt(
        schema_version=1,
        receipt_id=_string(raw.get("receipt_id"), "receipt_id", nonempty=True),
        operator_identity=_string(raw.get("operator_identity"), "operator_identity", nonempty=True),
        installation_id=_uuid(raw.get("installation_id"), "installation_id"),
        project_id=_uuid(raw.get("project_id"), "project_id"),
        content_hashes=content_hashes,
        permission_scope=freeze({name: "human" for name in operation_classes}),
        deployment_epoch=_positive_int(raw.get("deployment_epoch"), "deployment_epoch"),
        expires_at=_positive_int(raw.get("expires_at"), "expires_at"),
        revoked_at=_positive_int(raw.get("revocation_epoch"), "revocation_epoch"),
        native_limit=_string(raw.get("operator_action"), "operator_action", nonempty=True),
        enforcement_limit=_string(raw.get("operator_action"), "operator_action", nonempty=True),
        scope=freeze(raw.get("scope")),
        raw=freeze(raw),
    )


def validate_operation_record(raw_value: Any) -> OperationJournalRecord:
    raw = _mapping(
        raw_value,
        "operation",
        {
            "schema_version",
            "operation_id",
            "installation_id",
            "milestone_id",
            "operation_kind",
            "plan_digest",
            "grant_digest",
            "canonical_arguments_digest",
            "idempotency_key",
            "created_at",
            "owner_identity",
            "deployment_epoch",
            "operation_state",
            "native_ids",
            "reconciliation_evidence_refs",
            "terminal_result",
        },
    )
    _schema(raw, "operation", expected=1)
    return OperationJournalRecord(
        schema_version=1,
        operation_id=_string(raw.get("operation_id"), "operation_id", nonempty=True),
        installation_id=_uuid(raw.get("installation_id"), "installation_id"),
        milestone_id=_optional_string(raw.get("milestone_id"), "milestone_id"),
        operation_kind=_string(raw.get("operation_kind"), "operation_kind", nonempty=True),
        plan_digest=_hash(raw.get("plan_digest"), "plan_digest"),
        grant_digest=_hash(raw.get("grant_digest"), "grant_digest"),
        canonical_arguments_digest=_hash(raw.get("canonical_arguments_digest"), "canonical_arguments_digest"),
        idempotency_key=_string(raw.get("idempotency_key"), "idempotency_key", nonempty=True),
        created_at=_positive_int(raw.get("created_at"), "created_at"),
        owner_identity=_string(raw.get("owner_identity"), "owner_identity", nonempty=True),
        deployment_epoch=_positive_int(raw.get("deployment_epoch"), "deployment_epoch"),
        operation_state=_enum(raw.get("operation_state"), "operation_state", {"PREPARED", "ACKNOWLEDGED", "SENT", "UNCERTAIN", "SUCCEEDED", "FAILED"}),
        native_ids=tuple(_string(x, "native_ids[]", nonempty=True) for x in _list(raw.get("native_ids"), "native_ids")),
        reconciliation_evidence_refs=tuple(_string(x, "reconciliation_evidence_refs[]", nonempty=True) for x in _list(raw.get("reconciliation_evidence_refs"), "reconciliation_evidence_refs")),
        terminal_result=_optional_string(raw.get("terminal_result"), "terminal_result"),
        raw=freeze(raw),
    )


def validate_command_result(raw_value: Any) -> CommandResult:
    raw = _mapping(
        raw_value,
        "command_result",
        {
            "schema_version",
            "operation",
            "outcome",
            "checks",
            "warnings",
            "planned_changes",
            "applied_changes",
            "next_safe_action",
        },
    )
    _schema(raw, "command_result", expected=1)
    for banned in ("secret", "token", "password", "raw_invocation", "native_payload"):
        if banned in repr(raw).lower():
            fail("command_result", "secret_or_raw_payload", "command result must not include secrets or raw native payloads")
    return CommandResult(
        schema_version=1,
        operation=freeze(_mapping_any(raw.get("operation"), "operation")),
        outcome=_enum(raw.get("outcome"), "outcome", {"PASS", "FAIL", "UNKNOWN", "UNSUPPORTED", "NEEDS_INPUT"}),
        checks=tuple(freeze(_mapping_any(x, "checks[]")) for x in _list(raw.get("checks"), "checks")),
        warnings=tuple(_string(x, "warnings[]") for x in _list(raw.get("warnings"), "warnings")),
        planned_changes=tuple(freeze(_mapping_any(x, "planned_changes[]")) for x in _list(raw.get("planned_changes"), "planned_changes")),
        applied_changes=tuple(freeze(_mapping_any(x, "applied_changes[]")) for x in _list(raw.get("applied_changes"), "applied_changes")),
        next_safe_action=_string(raw.get("next_safe_action"), "next_safe_action", nonempty=True),
        raw=freeze(raw),
    )


def validate_change_plan(raw_value: Any) -> UnsupportedChangePlan:
    raw = _mapping_any(raw_value, "change_plan")
    version = raw.get("schema_version")
    if not isinstance(version, int) or isinstance(version, bool):
        fail("change_plan.schema_version", "unsupported_version", "schema_version must be an integer")
    return UnsupportedChangePlan(
        schema_version=version,
        kind=_enum(raw.get("kind"), "kind", {"repair", "validation", "recovery"}),
        plan_id=_string(raw.get("plan_id"), "plan_id", nonempty=True),
        raw=freeze(raw),
    )


def preview_v1_migration(data: bytes | str) -> MigrationPreview:
    raw_bytes = data if isinstance(data, bytes) else data.encode("utf-8")
    parsed = parse_yaml_subset(data, source_name="legacy-v1")
    raw = _mapping_any(parsed, "legacy")
    inventory = tuple(sorted(_flatten_paths(raw)))
    legacy_fields = tuple({"path": path, "type": _type_at_path(raw, path)} for path in inventory)
    draft = {
        "schema_version": 2,
        "setup_state": "draft",
        "project": {
            "id": raw.get("project_id"),
            "slug": raw.get("slug"),
            "name": raw.get("name"),
        },
    }
    unresolved = tuple(path for path in inventory if "secret" in path.lower() or "provider" in path.lower() or raw.get(path) is None)
    return MigrationPreview(
        schema_version=1,
        source_sha256=hashlib.sha256(raw_bytes).hexdigest(),
        legacy_fields=legacy_fields,
        draft_target=freeze(draft),
        unresolved_fields=unresolved,
    )


def _schema(raw: Mapping[str, Any], field: str, *, expected: int = 2) -> None:
    if raw.get("schema_version") != expected or isinstance(raw.get("schema_version"), bool):
        fail(f"{field}.schema_version", "unsupported_version", f"schema_version must be {expected}", line_for(raw, "schema_version"))


def _mapping(value: Any, field: str, allowed: set[str], *, optional: set[str] | None = None) -> Mapping[str, Any]:
    mapping = require_mapping(value, field)
    reject_unknowns(mapping, allowed, field)
    optional = optional or set()
    for key in allowed:
        if key not in optional and key not in mapping:
            fail(f"{field}.{key}" if field else key, "missing_required", "required field is missing")
    return mapping


def _mapping_any(value: Any, field: str) -> Mapping[str, Any]:
    if not isinstance(value, dict):
        fail(field, "invalid_type", "expected mapping")
    return value


def _list(value: Any, field: str) -> list[Any]:
    if not isinstance(value, (list, tuple)):
        fail(field, "invalid_type", "expected list")
    return list(value)


def _string(value: Any, field: str, *, nonempty: bool = False) -> str:
    if not isinstance(value, str):
        fail(field, "invalid_type", "expected string")
    if nonempty and not value:
        fail(field, "empty_string", "value must not be empty")
    return value


def _optional_string(value: Any, field: str) -> str | None:
    if value is None:
        return None
    return _string(value, field, nonempty=True)


def _enum(value: Any, field: str, allowed: set[str]) -> str:
    text = _string(value, field, nonempty=True)
    if text not in allowed:
        fail(field, "invalid_enum", f"expected one of {sorted(allowed)}")
    return text


def _const(value: Any, field: str, expected: Any) -> Any:
    if value != expected or isinstance(value, bool) != isinstance(expected, bool):
        fail(field, "unsupported_value", f"expected {expected!r}")
    return value


def _bool(value: Any, field: str) -> bool:
    if not isinstance(value, bool):
        fail(field, "invalid_type", "expected boolean")
    return value


def _uuid(value: Any, field: str) -> str:
    text = _string(value, field, nonempty=True)
    if not UUID_RE.match(text):
        fail(field, "invalid_uuid", "expected lowercase UUID")
    return text


def _slug(value: Any, field: str) -> str:
    text = _string(value, field, nonempty=True)
    if not SLUG_RE.match(text):
        fail(field, "invalid_slug", "expected lowercase slug")
    return text


def _hash(value: Any, field: str) -> str:
    text = _string(value, field, nonempty=True)
    if not HEX256_RE.match(text):
        fail(field, "invalid_digest", "expected lowercase sha256 digest")
    return text


def _hash_map(value: Any, field: str) -> Mapping[str, str]:
    mapping = _mapping_any(value, field)
    for key, digest in mapping.items():
        _string(key, f"{field}.key", nonempty=True)
        _hash(digest, f"{field}.{key}")
    return freeze(mapping)


def _reject_secret_values(value: Any, field: str) -> None:
    if isinstance(value, Mapping):
        for key, item in value.items():
            key_text = str(key).lower()
            if any(marker in key_text for marker in ("secret", "token", "password")) and item not in (None, "", []):
                fail(f"{field}.{key}", "secret_value_forbidden", "secret-bearing values are not allowed")
            _reject_secret_values(item, f"{field}.{key}")
    elif isinstance(value, (list, tuple)):
        for index, item in enumerate(value):
            _reject_secret_values(item, f"{field}[{index}]")


def _permission_map(value: Any, field: str) -> Mapping[str, str]:
    mapping = _mapping_any(value, field)
    for key, permission in mapping.items():
        _string(key, f"{field}.key", nonempty=True)
        if permission not in PERMISSIONS:
            fail(f"{field}.{key}", "invalid_permission", "permission must be denied, human, or autonomous")
    return mapping


def _positive_int(value: Any, field: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        fail(field, "invalid_integer", "expected non-negative integer")
    return value


def _optional_int(value: Any, field: str) -> int | None:
    if value is None:
        return None
    return _positive_int(value, field)


def _absolute(value: Any, field: str) -> str:
    text = _string(value, field, nonempty=True)
    if not text.startswith("/"):
        fail(field, "invalid_path", "expected absolute host path")
    return text


def _path(value: Any, field: str, metadata: MetadataSnapshot | None) -> str:
    text = _string(value, field, nonempty=True)
    parts = [part for part in text.split("/") if part]
    if text.startswith("/") or ".." in parts:
        fail(field, "path_escape", "path must be repository-relative and non-escaping")
    if metadata:
        if text in metadata.symlink_paths:
            fail(field, "symlink_escape", "path traverses an explicit symlink")
        if text.lower() in {path.lower() for path in metadata.casefold_paths} and text not in metadata.casefold_paths:
            fail(field, "case_collision", "path is case-ambiguous")
    return text


def _paths(value: Any, field: str, metadata: MetadataSnapshot | None, *, allow_empty: bool) -> tuple[str, ...]:
    items = _list(value, field)
    if not allow_empty and not items:
        fail(field, "missing_required", "configured record requires at least one path")
    return tuple(_path(item, f"{field}[]", metadata) for item in items)


def _command(value: Any, index: int, metadata: MetadataSnapshot | None) -> CommandSpec:
    field = f"verification.commands[{index}]"
    raw = _mapping(value, field, {"id", "argv", "cwd", "input_paths", "network_policy", "timeout_seconds", "approval_binding"})
    argv = raw.get("argv")
    if isinstance(argv, str):
        fail(f"{field}.argv", "shell_string_forbidden", "verification commands require argv list")
    argv_items = tuple(_string(item, f"{field}.argv[]", nonempty=True) for item in _list(argv, f"{field}.argv"))
    if not argv_items:
        fail(f"{field}.argv", "missing_required", "argv must not be empty")
    return CommandSpec(
        id=_string(raw.get("id"), f"{field}.id", nonempty=True),
        argv=argv_items,
        cwd=_path(raw.get("cwd"), f"{field}.cwd", metadata),
        input_paths=tuple(
            _path(path, f"{field}.input_paths[]", metadata)
            for path in _list(raw.get("input_paths"), f"{field}.input_paths")
        ),
        network_policy=_enum(raw.get("network_policy"), f"{field}.network_policy", {"none", "restricted", "allowed"}),
        timeout_seconds=_positive_int(raw.get("timeout_seconds"), f"{field}.timeout_seconds"),
        approval_binding=_optional_string(raw.get("approval_binding"), f"{field}.approval_binding"),
    )


def _content_ref(value: Any, field: str) -> Mapping[str, Any]:
    raw = _mapping(value, field, {"path", "reference", "digest"})
    _path(raw.get("path"), f"{field}.path", None)
    _string(raw.get("reference"), f"{field}.reference", nonempty=True)
    _hash(raw.get("digest"), f"{field}.digest")
    return freeze(raw)


def _reject_cycles(milestones: list[ExecutionMilestone]) -> None:
    graph = {milestone.id: milestone.depends_on for milestone in milestones}
    visiting: set[str] = set()
    visited: set[str] = set()

    def visit(mid: str) -> None:
        if mid in visited:
            return
        if mid in visiting:
            fail(f"milestones.{mid}.depends_on", "dependency_cycle", "dependency graph has a cycle")
        visiting.add(mid)
        for dep in graph[mid]:
            visit(dep)
        visiting.remove(mid)
        visited.add(mid)

    for milestone in milestones:
        visit(milestone.id)


def _flatten_paths(value: Any, prefix: str = "") -> list[str]:
    if isinstance(value, Mapping):
        result: list[str] = []
        for key, item in value.items():
            path = f"{prefix}.{key}" if prefix else str(key)
            result.append(path)
            result.extend(_flatten_paths(item, path))
        return result
    if isinstance(value, list):
        result = []
        for index, item in enumerate(value):
            result.extend(_flatten_paths(item, f"{prefix}[{index}]"))
        return result
    return []


def _type_at_path(value: Any, path: str) -> str:
    current: Any = value
    for part in path.replace("]", "").split("."):
        if "[" in part:
            key, index = part.split("[", 1)
            if key:
                current = current[key]
            current = current[int(index)]
        else:
            current = current[part]
    if current is None:
        return "null"
    if isinstance(current, bool):
        return "bool"
    if isinstance(current, int):
        return "int"
    if isinstance(current, str):
        return "str"
    if isinstance(current, list):
        return "list"
    if isinstance(current, Mapping):
        return "map"
    return type(current).__name__
