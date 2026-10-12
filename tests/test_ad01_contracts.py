from __future__ import annotations

import unittest
from dataclasses import FrozenInstanceError
from pathlib import Path

from autodev.contracts import (
    ContractError,
    MetadataSnapshot,
    TrustedOperatorContext,
    TrustedRegistry,
    classify_installation_identity,
    evaluate_readiness,
    evaluate_trusted_authority,
    intersect_permission_layers,
    load_execution_yaml,
    load_project_yaml,
    preview_v1_migration,
    validate_approval_receipt,
    validate_change_plan,
    validate_command_result,
    validate_installation_binding,
    validate_mutation_grant,
    validate_operation_record,
    validate_project,
    validate_validation_receipt,
    validation_receipt_applicability,
)
import autodev.contracts as contracts


ROOT = Path(__file__).resolve().parents[1]
DIGEST = "a" * 64
OTHER_DIGEST = "b" * 64
PROJECT_ID = "11111111-1111-1111-1111-111111111111"
INSTALLATION_ID = "22222222-2222-2222-2222-222222222222"


def fixture(name: str) -> str:
    return (ROOT / "fixtures" / "AD-01" / name).read_text(encoding="utf-8")


def metadata(**overrides: object) -> MetadataSnapshot:
    data = {
        "repo_realpath": "/workspace/autodev-v2",
        "git_common_dir_realpath": "/workspace/autodev-v2/.git",
        "project_id": PROJECT_ID,
        "installation_id": INSTALLATION_ID,
        "slug_registry": {"autodev-v2": PROJECT_ID},
    }
    data.update(overrides)
    return MetadataSnapshot(**data)


def grant() -> object:
    return validate_mutation_grant(
        {
            "schema_version": 1,
            "grant_id": "grant-1",
            "operator_identity": "operator:human",
            "operator_action": "approve-mutation",
            "installation_id": INSTALLATION_ID,
            "project_id": PROJECT_ID,
            "operation_classes": ["write-fixture"],
            "repository_membership_rule": "same-git-common-dir",
            "managed_worktree_membership_rule": "same-repo-realpath",
            "protected_files": ["ROADMAP.yaml"],
            "protected_refs": ["main"],
            "allowed_routes": ["local-tests"],
            "artifact_hashes": {"docs/plans/AD-01.md": DIGEST},
            "resource_constraints": {"network": "none"},
            "issued_at": 10,
            "expires_at": 100,
            "revocation_epoch": 0,
            "deployment_epoch": 7,
            "enforcement_backend": "policy-enforced",
            "content_digest": DIGEST,
        }
    )


def approval() -> object:
    return validate_approval_receipt(
        {
            "schema_version": 1,
            "receipt_id": "receipt-1",
            "operator_identity": "operator:human",
            "operator_action": "approve-plan",
            "project_id": PROJECT_ID,
            "installation_id": INSTALLATION_ID,
            "artifact_digests": {"docs/plans/AD-01.md": DIGEST},
            "operation_classes": ["write-fixture"],
            "scope": {"paths": ["src/autodev/contracts"]},
            "issued_at": 10,
            "expires_at": 100,
            "revocation_epoch": 0,
            "deployment_epoch": 7,
            "content_digest": DIGEST,
        }
    )


def live_receipt(**overrides: object) -> object:
    data = {
        "schema_version": 1,
        "gate_id": "gate-1",
        "evidence_class": "LIVE",
        "probe_id": "probe-1",
        "installation_id": INSTALLATION_ID,
        "project_id": PROJECT_ID,
        "invocation_source": "unit-test",
        "observed_at": 10,
        "expires_at": 100,
        "capability_fingerprint": DIGEST,
        "bound_hashes": {"PROJECT.yaml": DIGEST},
        "repo_revision": "abc123",
        "dirty_input_fingerprint": OTHER_DIGEST,
        "profile_identity": "profile:local",
        "process_generation": "process-1",
        "route_identity": "route:local",
        "native_trace_refs": ["trace-1"],
        "allowed_effects": [],
        "observed_effects": [],
        "cleanup_state": "COMPLETE",
        "result": "PASS",
        "invalidation_keys": ["PROJECT.yaml"],
    }
    data.update(overrides)
    return validate_validation_receipt(data)


class AD01ProjectExecutionTests(unittest.TestCase):
    def test_draft_loads_but_denies_enable_and_dispatch(self) -> None:
        project = load_project_yaml(fixture("project-draft.yaml"), metadata())
        self.assertEqual(project.setup_state, "draft")
        readiness = evaluate_readiness(
            repository="ALIGNED",
            deployment="ABSENT",
            deployment_supported=False,
            certification="NOT_RUN",
            required_validation_receipts_current=False,
            operator_grant_current=False,
            grant_content_bound=False,
            approval_receipt_current=False,
            approval_content_bound=False,
            enforcement="POLICY_ONLY",
            delivery="NOT_TESTED",
            tested_delivery_current=False,
            ownership_conflict=False,
            drift_conflict=False,
            eligible_approved_milestones=0,
            dependencies_satisfied=False,
            base_policy_satisfied=False,
            execution_state="IDLE",
            admission_state="UNKNOWN",
            quota_state="UNKNOWN",
            schedule_state="UNKNOWN",
        )
        self.assertTrue(readiness.aligned)
        self.assertFalse(readiness.enable_ready)
        self.assertFalse(readiness.dispatch_ready)
        self.assertIn("DEPLOYMENT_NOT_CONFIGURED", readiness.reason_codes)

    def test_configured_project_and_execution_fixture_load(self) -> None:
        project = load_project_yaml(fixture("project-configured.yaml"), metadata())
        index = load_execution_yaml(fixture("execution.yaml"), project)
        self.assertEqual(project.verification_commands[0].network_policy, "none")
        self.assertEqual(index.milestones[0].approval["state"], "approved")

    def test_schema_and_path_fail_closed_with_field_codes(self) -> None:
        bad_version = fixture("project-configured.yaml").replace("schema_version: 2", "schema_version: 99", 1)
        with self.assertRaises(ContractError) as raised:
            load_project_yaml(bad_version, metadata())
        self.assertEqual(raised.exception.issues[0].field, "schema_version")
        self.assertEqual(raised.exception.issues[0].code, "unsupported_version")
        raw = {
            "schema_version": 2,
            "setup_state": "configured",
            "project": {"id": PROJECT_ID, "slug": "autodev-v2", "name": "AutoDev"},
            "sources": {"requirements": ["/etc/passwd"], "context": ["context/SHARED-INVARIANTS.md"], "discovery": {"roots": ["src"]}, "execution_index": ".agent/EXECUTION.yaml"},
            "execution": {"harness": "gajae", "workflow": "approved_roadmap_only", "base_policy": "dependencies_integrated", "target_ref": "refs/heads/main", "max_active_milestones": 1, "max_primary_actions_per_cycle": 1},
            "verification": {"commands": [], "acceptance_sources": ["milestones/AD-01.md"], "require_independent_review": True},
            "authority": {"requested": {"write-fixture": "human"}},
        }
        with self.assertRaises(ContractError) as path_error:
            validate_project(raw, metadata())
        self.assertEqual(path_error.exception.issues[0].code, "path_escape")

    def test_permissions_and_execution_graph_fail_closed(self) -> None:
        project = load_project_yaml(fixture("project-configured.yaml"), metadata())
        bad_permission = fixture("project-configured.yaml").replace("write-fixture: human", "write-fixture: maybe")
        with self.assertRaises(ContractError) as permission_error:
            load_project_yaml(bad_permission, metadata())
        self.assertEqual(permission_error.exception.issues[0].code, "invalid_permission")
        cyclic = fixture("execution.yaml").replace("depends_on: []", "depends_on: [AD-01]")
        with self.assertRaises(ContractError) as cycle_error:
            load_execution_yaml(cyclic, project)
        self.assertEqual(cycle_error.exception.issues[0].code, "dependency_cycle")
        missing_receipt = fixture("execution.yaml").replace("receipt_ref: receipt-1", "receipt_ref: null")
        loaded = load_execution_yaml(missing_receipt, project)
        self.assertIsNone(loaded.milestones[0].approval["receipt_ref"])


class AD01AuthorityReadinessIdentityTests(unittest.TestCase):
    def test_trusted_context_required_and_permission_layers_intersect(self) -> None:
        project = load_project_yaml(fixture("project-configured.yaml"), metadata())
        trusted = TrustedRegistry(approval_receipts={"receipt-1": approval()}, mutation_grants={"grant-1": grant()})
        context = TrustedOperatorContext(
            operator_identity="operator:human",
            now=50,
            project_id=PROJECT_ID,
            installation_id=INSTALLATION_ID,
            profile_identity="profile:local",
            process_generation="process-1",
            deployment_epoch=7,
            source_digests={"docs/plans/AD-01.md": DIGEST},
            revocation_epoch=0,
            operator_grants={"grant-1": grant()},
            native_limits={"write-fixture": "human"},
            enforcement_limits={"write-fixture": "human"},
        )
        decision = evaluate_trusted_authority(
            project=project,
            approval_ref="receipt-1",
            grant_ref="grant-1",
            registry=trusted,
            context=context,
            operation_class="write-fixture",
            requested_paths=("src/autodev/contracts",),
        )
        self.assertTrue(decision.allowed)
        self.assertEqual(decision.effective_permissions["write-fixture"], "human")
        for paths, operation_path, expected in (
            ((), "src/autodev/contracts", True),
            (("ROADMAP.yaml",), "src/autodev/contracts", False),
            (("src/autodev/contracts",), "ROADMAP.yaml", False),
        ):
            with self.subTest(paths=paths, operation_path=operation_path):
                scoped = evaluate_trusted_authority(
                    project=project,
                    approval_ref="receipt-1",
                    grant_ref="grant-1",
                    registry=trusted,
                    context=context,
                    operation_class="write-fixture",
                    requested_paths=paths,
                    operation_path=operation_path,
                )
                self.assertEqual(scoped.allowed, expected)
        self.assertEqual(
            intersect_permission_layers(
                {"write-fixture": "autonomous"},
                {"write-fixture": "human"},
                {"write-fixture": "autonomous"},
                {"write-fixture": "human"},
            )["write-fixture"],
            "human",
        )
        forged = evaluate_trusted_authority(
            project=project,
            approval_ref="receipt-1",
            grant_ref="grant-1",
            registry=TrustedRegistry(approval_receipts={}, mutation_grants={}),
            context=context,
            operation_class="write-fixture",
        )
        self.assertFalse(forged.allowed)
        self.assertIn("APPROVAL_NOT_IN_TRUSTED_REGISTRY", forged.reason_codes)
        out_of_scope = evaluate_trusted_authority(
            project=project,
            approval_ref="receipt-1",
            grant_ref="grant-1",
            registry=trusted,
            context=context,
            operation_class="write-fixture",
            requested_paths=("ROADMAP.yaml",),
        )
        self.assertFalse(out_of_scope.allowed)
        self.assertIn("APPROVAL_SCOPE_MISMATCH", out_of_scope.reason_codes)

    def test_authority_requires_context_grant_and_nonempty_content_bindings(self) -> None:
        self.assertTrue(hasattr(contracts, "evaluate_authority"))
        project = load_project_yaml(fixture("project-configured.yaml"), metadata())
        with self.assertRaises(ContractError):
            validate_mutation_grant({**grant().raw, "artifact_hashes": {}})
        with self.assertRaises(ContractError):
            validate_approval_receipt({**approval().raw, "artifact_digests": {}})
        context = TrustedOperatorContext(
            operator_identity="operator:human",
            now=50,
            project_id=PROJECT_ID,
            installation_id=INSTALLATION_ID,
            profile_identity="profile:local",
            process_generation="process-1",
            deployment_epoch=7,
            source_digests={"docs/plans/AD-01.md": DIGEST},
            revocation_epoch=0,
            operator_grants={},
            native_limits={"write-fixture": "human"},
            enforcement_limits={"write-fixture": "human"},
        )
        registry_only = evaluate_trusted_authority(
            project=project,
            approval_ref="receipt-1",
            grant_ref="grant-1",
            registry=TrustedRegistry(approval_receipts={"receipt-1": approval()}, mutation_grants={"grant-1": grant()}),
            context=context,
            operation_class="write-fixture",
        )
        self.assertFalse(registry_only.allowed)
        self.assertIn("OPERATOR_GRANT_NOT_IN_TRUSTED_CONTEXT", registry_only.reason_codes)

    def test_receipt_applicability_denies_simulated_and_changed_context(self) -> None:
        simulated = live_receipt(evidence_class="SIMULATED", native_trace_refs=[])
        ok, reasons = validation_receipt_applicability(
            simulated,
            project_id=PROJECT_ID,
            installation_id=INSTALLATION_ID,
            profile_identity="profile:local",
            process_generation="process-1",
            now=50,
            repo_revision="abc123",
            dirty_fingerprint=OTHER_DIGEST,
            required_hashes={"PROJECT.yaml": DIGEST},
            require_live=True,
            allowed_effects=set(),
        )
        self.assertFalse(ok)
        self.assertIn("simulated_receipt_not_live", reasons)
        live = live_receipt()
        ok, reasons = validation_receipt_applicability(
            live,
            project_id=PROJECT_ID,
            installation_id=INSTALLATION_ID,
            profile_identity="profile:other",
            process_generation="process-1",
            now=50,
            repo_revision="abc123",
            dirty_fingerprint=OTHER_DIGEST,
            required_hashes={"PROJECT.yaml": DIGEST},
            require_live=True,
            allowed_effects=set(),
        )
        self.assertFalse(ok)
        self.assertIn("profile_mismatch", reasons)
        future = live_receipt(observed_at=99)
        ok, reasons = validation_receipt_applicability(
            future,
            project_id=PROJECT_ID,
            installation_id=INSTALLATION_ID,
            profile_identity="profile:local",
            process_generation="process-1",
            now=50,
            repo_revision="abc123",
            dirty_fingerprint=OTHER_DIGEST,
            required_hashes={"PROJECT.yaml": DIGEST},
            require_live=True,
            allowed_effects=set(),
        )
        self.assertFalse(ok)
        self.assertIn("receipt_observed_in_future", reasons)
        effect = live_receipt(allowed_effects=[], observed_effects=["write"])
        ok, reasons = validation_receipt_applicability(
            effect,
            project_id=PROJECT_ID,
            installation_id=INSTALLATION_ID,
            profile_identity="profile:local",
            process_generation="process-1",
            now=50,
            repo_revision="abc123",
            dirty_fingerprint=OTHER_DIGEST,
            required_hashes={"PROJECT.yaml": DIGEST},
            require_live=True,
            allowed_effects={"write"},
        )
        self.assertFalse(ok)
        self.assertIn("effect_outside_receipt_allowed_set", reasons)

    def test_progressive_readiness_truth_table_and_schedule_axis(self) -> None:
        base = {
            "repository": "ALIGNED",
            "deployment": "CONFIGURED",
            "deployment_supported": True,
            "certification": "PASSED",
            "required_validation_receipts_current": True,
            "operator_grant_current": True,
            "grant_content_bound": True,
            "approval_receipt_current": True,
            "approval_content_bound": True,
            "enforcement": "ENFORCED",
            "delivery": "DELIVERED",
            "tested_delivery_current": True,
            "ownership_conflict": False,
            "drift_conflict": False,
            "eligible_approved_milestones": 1,
            "dependencies_satisfied": True,
            "base_policy_satisfied": True,
            "execution_state": "IDLE",
            "admission_state": "ALLOW",
            "quota_state": "AVAILABLE",
            "schedule_state": "UNKNOWN",
        }
        aligned_only = evaluate_readiness(**{**base, "deployment": "ABSENT"})
        self.assertTrue(aligned_only.aligned)
        self.assertFalse(aligned_only.enable_ready)
        enable_only = evaluate_readiness(**{**base, "eligible_approved_milestones": 0})
        self.assertTrue(enable_only.enable_ready)
        self.assertFalse(enable_only.dispatch_ready)
        dispatch = evaluate_readiness(**base)
        self.assertTrue(dispatch.dispatch_ready)
        self.assertEqual(dispatch.schedule_state, "UNKNOWN")
        unknown_conflict = evaluate_readiness(**{**base, "ownership_conflict": None})
        self.assertFalse(unknown_conflict.enable_ready)
        self.assertIn("CONFLICT_EVIDENCE_UNKNOWN", unknown_conflict.reason_codes)
        negative_count = evaluate_readiness(**{**base, "eligible_approved_milestones": -1})
        self.assertFalse(negative_count.dispatch_ready)
        self.assertIn("NO_ELIGIBLE_APPROVED_MILESTONE", negative_count.reason_codes)
        with self.assertRaises(ValueError):
            evaluate_readiness(**{**base, "dependencies_satisfied": 1})

    def test_clone_identity_is_not_silently_adopted(self) -> None:
        project = load_project_yaml(fixture("project-configured.yaml"), metadata())
        binding = validate_installation_binding(
            {
                "schema_version": 1,
                "installation_id": INSTALLATION_ID,
                "project_id": PROJECT_ID,
                "repo_realpath": "/workspace/autodev-v2",
                "git_common_dir_realpath": "/workspace/autodev-v2/.git",
                "profile_identity": "profile:local",
                "service_identity": "service:none",
                "root_binding_policy": "exact_realpath",
                "runtime_capability_manifest_ref": "capabilities.json",
                "model_routes": {},
                "auth_account_refs": [],
                "resource_policy": {},
                "deployment_grant_ref": "grant-1",
                "skill_hash": DIGEST,
                "delivery_target_ref": "delivery-local",
                "cron_id": None,
                "cron_ownership": "absent",
                "desired_enabled": False,
                "deployment_epoch": 7,
                "project_slug": "autodev-v2",
            }
        )
        clone = classify_installation_identity(
            project,
            binding,
            metadata(repo_realpath="/workspace/clone", git_common_dir_realpath="/workspace/clone/.git"),
        )
        self.assertEqual(clone.classification, "NEW_INSTALLATION_REQUIRED")


class AD01MiscContractTests(unittest.TestCase):
    def test_immutability_and_command_result_boundaries(self) -> None:
        project = load_project_yaml(fixture("project-configured.yaml"), metadata())
        with self.assertRaises(FrozenInstanceError):
            project.name = "changed"  # type: ignore[misc]
        with self.assertRaises(TypeError):
            project.raw["project"] = {}  # type: ignore[index]
        validate_command_result(
            {
                "schema_version": 1,
                "operation": {"id": "operation-1"},
                "outcome": "NEEDS_INPUT",
                "checks": [],
                "warnings": [],
                "planned_changes": [],
                "applied_changes": [],
                "next_safe_action": "ask-operator",
            }
        )
        with self.assertRaises(ContractError):
            validate_command_result(
                {
                    "schema_version": 1,
                    "operation": {"id": "operation-1", "token": "secret-value"},
                    "outcome": "PASS",
                    "checks": [],
                    "warnings": [],
                    "planned_changes": [],
                    "applied_changes": [],
                    "next_safe_action": "none",
                }
            )
        result = validate_command_result(
            {
                "schema_version": 1,
                "operation": {"id": "operation-1"},
                "outcome": "UNSUPPORTED",
                "checks": [],
                "warnings": [],
                "planned_changes": [],
                "applied_changes": [],
                "next_safe_action": "none",
            }
        )
        self.assertEqual(result.outcome, "UNSUPPORTED")
        operation = validate_operation_record(
            {
                "schema_version": 1,
                "operation_id": "operation-1",
                "installation_id": INSTALLATION_ID,
                "milestone_id": "AD-01",
                "operation_kind": "local-validation",
                "plan_digest": DIGEST,
                "grant_digest": DIGEST,
                "canonical_arguments_digest": DIGEST,
                "idempotency_key": "idem-1",
                "created_at": 10,
                "owner_identity": "operator:human",
                "deployment_epoch": 7,
                "operation_state": "UNCERTAIN",
                "native_ids": [],
                "reconciliation_evidence_refs": [],
                "terminal_result": None,
            }
        )
        self.assertEqual(operation.operation_state, "UNCERTAIN")

    def test_migration_preview_and_unsupported_change_plan_are_write_free(self) -> None:
        preview = preview_v1_migration(
            "project_id: 11111111-1111-1111-1111-111111111111\n"
            "slug: legacy\n"
            "provider_token: unresolved\n"
        )
        self.assertFalse(preview.applicable)
        self.assertFalse(preview.writes_performed)
        self.assertIn("provider_token", preview.field_inventory)
        plan = validate_change_plan({"schema_version": 2, "kind": "repair", "plan_id": "plan-1"})
        self.assertEqual(plan.reason, "UNSUPPORTED")


if __name__ == "__main__":
    unittest.main()
