from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping

from .model import ApprovalReceipt, MutationGrant, ProjectContract, ValidationReceipt


@dataclass(frozen=True)
class AuthorityDecision:
    allowed: bool
    effective_permissions: Mapping[str, str]
    reason_codes: tuple[str, ...]


@dataclass(frozen=True)
class TrustedRegistry:
    approval_receipts: Mapping[str, ApprovalReceipt]
    mutation_grants: Mapping[str, MutationGrant]


@dataclass(frozen=True)
class TrustedOperatorContext:
    operator_identity: str
    now: int
    project_id: str
    installation_id: str
    profile_identity: str
    process_generation: str
    deployment_epoch: int
    source_digests: Mapping[str, str]
    revocation_epoch: int
    operator_grants: Mapping[str, MutationGrant]
    native_limits: Mapping[str, str]
    enforcement_limits: Mapping[str, str]


def intersect_permissions(requested: Mapping[str, str], granted: Mapping[str, str]) -> dict[str, str]:
    rank = {"denied": 0, "human": 1, "autonomous": 2}
    names = set(requested) | set(granted)
    effective: dict[str, str] = {}
    for name in names:
        req = requested.get(name, "denied")
        grant = granted.get(name, "denied")
        effective[name] = req if rank[req] <= rank[grant] else grant
    return effective


def intersect_permission_layers(*layers: Mapping[str, str]) -> dict[str, str]:
    rank = {"denied": 0, "human": 1, "autonomous": 2}
    names: set[str] = set()
    for layer in layers:
        names.update(layer)
    effective: dict[str, str] = {}
    for name in names:
        selected = "autonomous"
        for layer in layers:
            value = layer.get(name, "denied")
            if rank[value] < rank[selected]:
                selected = value
        effective[name] = selected
    return effective


def evaluate_authority(
    *,
    project: ProjectContract,
    approval_ref: str,
    grant_ref: str,
    registry: TrustedRegistry,
    content_hashes: Mapping[str, str],
    installation_id: str,
    deployment_epoch: int,
    now: int,
) -> AuthorityDecision:
    return AuthorityDecision(False, {}, ("TRUSTED_OPERATOR_CONTEXT_REQUIRED",))


def evaluate_trusted_authority(
    *,
    project: ProjectContract,
    approval_ref: str,
    grant_ref: str,
    registry: TrustedRegistry,
    context: TrustedOperatorContext,
    operation_class: str,
    requested_paths: tuple[str, ...] = (),
    operation_path: str | None = None,
) -> AuthorityDecision:
    reasons: list[str] = []
    receipt = registry.approval_receipts.get(approval_ref)
    grant = context.operator_grants.get(grant_ref)
    if receipt is None:
        reasons.append("APPROVAL_NOT_IN_TRUSTED_REGISTRY")
    if grant is None:
        reasons.append("OPERATOR_GRANT_NOT_IN_TRUSTED_CONTEXT")
    if receipt is None or grant is None:
        return AuthorityDecision(False, {}, tuple(reasons))

    for label, record in (("APPROVAL", receipt), ("GRANT", grant)):
        if record.operator_identity != context.operator_identity:
            reasons.append(f"{label}_OPERATOR_MISMATCH")
        if record.project_id != context.project_id or record.project_id != project.project_id:
            reasons.append(f"{label}_PROJECT_MISMATCH")
        if record.installation_id != context.installation_id:
            reasons.append(f"{label}_INSTALLATION_MISMATCH")
        if record.deployment_epoch != context.deployment_epoch:
            reasons.append(f"{label}_STALE_EPOCH")
        if record.expires_at <= context.now:
            reasons.append(f"{label}_EXPIRED")
        if record.revoked_at is not None and record.revoked_at > 0 and record.revoked_at <= context.revocation_epoch:
            reasons.append(f"{label}_REVOKED")

    if operation_class not in grant.operation_classes:
        reasons.append("OPERATION_CLASS_NOT_GRANTED")
    if operation_class not in receipt.permission_scope:
        reasons.append("OPERATION_CLASS_NOT_APPROVED")
    scoped_paths = tuple(receipt.scope.get("paths", ())) if receipt.scope else ()
    for path in requested_paths + (() if operation_path is None else (operation_path,)):
        if path not in scoped_paths:
            reasons.append("APPROVAL_SCOPE_MISMATCH")
            break
    if not receipt.content_hashes:
        reasons.append("APPROVAL_NOT_CONTENT_BOUND")
    if not grant.approved_product_artifact_hashes:
        reasons.append("GRANT_NOT_CONTENT_BOUND")
    for path, digest in receipt.content_hashes.items():
        if context.source_digests.get(path) != digest:
            reasons.append("APPROVAL_NOT_CONTENT_BOUND")
            break
    for path, digest in grant.approved_product_artifact_hashes.items():
        if context.source_digests.get(path) != digest:
            reasons.append("GRANT_NOT_CONTENT_BOUND")
            break
    effective = intersect_permission_layers(
        project.requested_authority,
        grant.permission_scope,
        context.native_limits,
        context.enforcement_limits,
    )
    if effective.get(operation_class, "denied") == "denied":
        reasons.append("NO_EFFECTIVE_PERMISSION")
    return AuthorityDecision(not reasons, effective, tuple(dict.fromkeys(reasons)))


def validation_receipt_applicability(
    receipt: ValidationReceipt,
    *,
    project_id: str,
    installation_id: str,
    profile_identity: str,
    process_generation: str,
    now: int,
    repo_revision: str,
    dirty_fingerprint: str,
    required_hashes: Mapping[str, str],
    require_live: bool,
    allowed_effects: set[str],
) -> tuple[bool, tuple[str, ...]]:
    reasons: list[str] = []
    if receipt.result != "PASS":
        reasons.append("receipt_not_pass")
    if require_live and receipt.evidence_class != "LIVE":
        reasons.append("simulated_receipt_not_live")
    if require_live and not receipt.native_trace_refs:
        reasons.append("native_trace_missing")
    if receipt.project_id != project_id:
        reasons.append("project_mismatch")
    if receipt.installation_id != installation_id:
        reasons.append("installation_mismatch")
    if receipt.profile_identity != profile_identity:
        reasons.append("profile_mismatch")
    if receipt.process_generation != process_generation:
        reasons.append("process_generation_mismatch")
    if receipt.expires_at <= now:
        reasons.append("receipt_expired")
    if receipt.observed_at > now:
        reasons.append("receipt_observed_in_future")
    if receipt.repo_revision != repo_revision:
        reasons.append("repo_revision_changed")
    if receipt.dirty_fingerprint != dirty_fingerprint:
        reasons.append("dirty_fingerprint_changed")
    for key, value in required_hashes.items():
        if receipt.relevant_hashes.get(key) != value:
            reasons.append("relevant_hash_changed")
            break
    if receipt.cleanup_state != "COMPLETE":
        reasons.append("cleanup_incomplete")
    if set(receipt.observed_effects) - set(receipt.allowed_effects):
        reasons.append("effect_outside_allowed_set")
        reasons.append("effect_outside_receipt_allowed_set")
    if set(receipt.observed_effects) - allowed_effects:
        reasons.append("effect_outside_allowed_set")
    return not reasons, tuple(dict.fromkeys(reasons))
