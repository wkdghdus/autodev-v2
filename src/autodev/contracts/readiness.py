from __future__ import annotations

from dataclasses import dataclass


REPOSITORY_STATES = {"DRAFT", "ALIGNED", "INVALID"}
DEPLOYMENT_STATES = {"ABSENT", "CONFIGURED", "PARTIAL", "DRIFTED"}
CERTIFICATION_STATES = {"NOT_RUN", "PASSED", "FAILED", "STALE", "BLOCKED_EXTERNAL"}
ADMISSION_STATES = {"ALLOW", "DENY", "UNKNOWN"}
SCHEDULE_STATES = {"ABSENT", "PAUSED", "ENABLED", "UNKNOWN"}
EXECUTION_STATES = {
    "IDLE",
    "EXECUTING",
    "WAITING_FOR_ANSWER",
    "VERIFYING",
    "FAILED_REPAIRABLE",
    "UNCERTAIN",
    "HUMAN_BLOCKED",
    "VERIFIED_UNMERGED",
    "INTEGRATED",
}
RESOURCE_STATES = {"AVAILABLE", "BLOCKED_QUOTA", "UNKNOWN"}
DELIVERY_STATES = {"NOT_TESTED", "DELIVERED", "FAILED", "UNKNOWN"}
ENFORCEMENT_STATES = {"POLICY_ONLY", "ENFORCED"}


@dataclass(frozen=True)
class Readiness:
    aligned: bool
    enable_ready: bool
    dispatch_ready: bool
    schedule_state: str
    reason_codes: tuple[str, ...]


def evaluate_readiness(
    *,
    repository: str,
    deployment: str,
    deployment_supported: bool,
    certification: str,
    required_validation_receipts_current: bool,
    operator_grant_current: bool,
    grant_content_bound: bool,
    approval_receipt_current: bool,
    approval_content_bound: bool,
    enforcement: str,
    delivery: str,
    tested_delivery_current: bool,
    ownership_conflict: bool,
    drift_conflict: bool,
    eligible_approved_milestones: int,
    dependencies_satisfied: bool,
    base_policy_satisfied: bool,
    quota_state: str,
    execution_state: str,
    admission_state: str,
    schedule_state: str,
) -> Readiness:
    for name, value in {
        "deployment_supported": deployment_supported,
        "required_validation_receipts_current": required_validation_receipts_current,
        "operator_grant_current": operator_grant_current,
        "grant_content_bound": grant_content_bound,
        "approval_receipt_current": approval_receipt_current,
        "approval_content_bound": approval_content_bound,
        "tested_delivery_current": tested_delivery_current,
        "dependencies_satisfied": dependencies_satisfied,
        "base_policy_satisfied": base_policy_satisfied,
    }.items():
        _check_bool(name, value)
    invalid_milestone_count = False
    if not isinstance(eligible_approved_milestones, int) or isinstance(eligible_approved_milestones, bool):
        raise ValueError("eligible_approved_milestones must be an integer")
    _check_state("repository", repository, REPOSITORY_STATES)
    _check_state("deployment", deployment, DEPLOYMENT_STATES)
    _check_state("certification", certification, CERTIFICATION_STATES)
    _check_state("enforcement", enforcement, ENFORCEMENT_STATES)
    _check_state("delivery", delivery, DELIVERY_STATES)
    _check_state("resource", quota_state, RESOURCE_STATES)
    _check_state("execution", execution_state, EXECUTION_STATES)
    _check_state("admission", admission_state, ADMISSION_STATES)
    _check_state("schedule", schedule_state, SCHEDULE_STATES)
    reasons: list[str] = []
    aligned = repository == "ALIGNED"
    if not aligned:
        reasons.append("REPOSITORY_NOT_ALIGNED")
    if deployment != "CONFIGURED":
        reasons.append("DEPLOYMENT_NOT_CONFIGURED")
    if not deployment_supported:
        reasons.append("DEPLOYMENT_UNSUPPORTED")
    if certification != "PASSED" or not required_validation_receipts_current:
        reasons.append("CERTIFICATION_NOT_PASSED")
    if not operator_grant_current:
        reasons.append("OPERATOR_GRANT_MISSING_OR_STALE")
    if not grant_content_bound:
        reasons.append("GRANT_NOT_CONTENT_BOUND")
    if not approval_receipt_current:
        reasons.append("APPROVAL_RECEIPT_MISSING_OR_STALE")
    if not approval_content_bound:
        reasons.append("APPROVAL_NOT_CONTENT_BOUND")
    if enforcement != "ENFORCED":
        reasons.append("ENFORCEMENT_NOT_ASSURED")
    if delivery != "DELIVERED" or not tested_delivery_current:
        reasons.append("DELIVERY_NOT_TESTED")
    if ownership_conflict is None or drift_conflict is None:
        reasons.append("CONFLICT_EVIDENCE_UNKNOWN")
    elif not isinstance(ownership_conflict, bool) or not isinstance(drift_conflict, bool):
        raise ValueError("conflict evidence must be bool or None")
    if ownership_conflict is True:
        reasons.append("OWNERSHIP_CONFLICT")
    if drift_conflict is True:
        reasons.append("DRIFT_CONFLICT")
    enable_blockers = {
        "REPOSITORY_NOT_ALIGNED",
        "DEPLOYMENT_NOT_CONFIGURED",
        "DEPLOYMENT_UNSUPPORTED",
        "CERTIFICATION_NOT_PASSED",
        "OPERATOR_GRANT_MISSING_OR_STALE",
        "GRANT_NOT_CONTENT_BOUND",
        "APPROVAL_RECEIPT_MISSING_OR_STALE",
        "APPROVAL_NOT_CONTENT_BOUND",
        "ENFORCEMENT_NOT_ASSURED",
        "DELIVERY_NOT_TESTED",
        "OWNERSHIP_CONFLICT",
        "DRIFT_CONFLICT",
        "CONFLICT_EVIDENCE_UNKNOWN",
    }
    enable_ready = not any(reason in enable_blockers for reason in reasons)
    if invalid_milestone_count or eligible_approved_milestones <= 0:
        reasons.append("NO_ELIGIBLE_APPROVED_MILESTONE")
    if eligible_approved_milestones > 1:
        reasons.append("MULTIPLE_ELIGIBLE_APPROVED_MILESTONES")
    if not dependencies_satisfied:
        reasons.append("DEPENDENCIES_UNSATISFIED")
    if not base_policy_satisfied:
        reasons.append("BASE_POLICY_UNSATISFIED")
    if execution_state != "IDLE":
        reasons.append("EXECUTION_NOT_IDLE")
    if admission_state != "ALLOW":
        reasons.append("ADMISSION_NOT_ALLOW")
    if quota_state != "AVAILABLE":
        reasons.append("RESOURCE_NOT_AVAILABLE")
    dispatch_blockers = {
        "NO_ELIGIBLE_APPROVED_MILESTONE",
        "MULTIPLE_ELIGIBLE_APPROVED_MILESTONES",
        "DEPENDENCIES_UNSATISFIED",
        "BASE_POLICY_UNSATISFIED",
        "EXECUTION_NOT_IDLE",
        "ADMISSION_NOT_ALLOW",
        "RESOURCE_NOT_AVAILABLE",
    }
    dispatch_ready = enable_ready and not any(
        reason in dispatch_blockers for reason in reasons
    )
    return Readiness(aligned, enable_ready, dispatch_ready, schedule_state, tuple(dict.fromkeys(reasons)))


def _check_state(name: str, value: str, allowed: set[str]) -> None:
    if value not in allowed:
        raise ValueError(f"{name} state must be one of {sorted(allowed)}")


def _check_bool(name: str, value: bool) -> None:
    if not isinstance(value, bool):
        raise ValueError(f"{name} must be bool")
