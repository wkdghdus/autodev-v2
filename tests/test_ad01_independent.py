from __future__ import annotations

from dataclasses import FrozenInstanceError
from itertools import product
import unittest

from autodev.contracts import (
    ApprovalReceipt,
    CommandResult,
    ContractError,
    ProjectContract,
    MetadataSnapshot,
    TrustedOperatorContext,
    TrustedRegistry,
    classify_installation_identity,
    evaluate_execution_eligibility,
    evaluate_readiness,
    evaluate_trusted_authority,
    intersect_permission_layers,
    preview_v1_migration,
    validate_project,
    validate_approval_receipt,
    validate_command_result,
    validate_execution,
    validate_installation_binding,
    validate_mutation_grant,
    validate_operation_record,
    validate_validation_receipt,
    validation_receipt_applicability,
)
from autodev.contracts.authority import evaluate_authority
from autodev.contracts.yaml_subset import parse_yaml_subset


DIGEST = "a" * 64
OTHER_DIGEST = "b" * 64
PROJECT_ID = "11111111-1111-1111-1111-111111111111"
INSTALLATION_ID = "22222222-2222-2222-2222-222222222222"
PERMISSION_RANK = {"denied": 0, "human": 1, "autonomous": 2}
PERMISSIONS = tuple(PERMISSION_RANK)


def installation_binding_fixture() -> dict[str, object]:
    return {
        "schema_version": 1,
        "installation_id": INSTALLATION_ID,
        "project_id": PROJECT_ID,
        "repo_realpath": "/workspace/autodev-v2",
        "git_common_dir_realpath": "/workspace/autodev-v2/.git",
        "profile_identity": "profile:local",
        "service_identity": "service:none",
        "root_binding_policy": "exact_realpath",
        "runtime_capability_manifest_ref": "capabilities.json",
        "model_routes": {"executor": "gpt-5.5"},
        "auth_account_refs": [],
        "resource_policy": {"network": "none"},
        "deployment_grant_ref": "grant-1",
        "skill_hash": DIGEST,
        "delivery_target_ref": "delivery-local",
        "cron_id": None,
        "cron_ownership": "absent",
        "desired_enabled": False,
        "deployment_epoch": 7,
        "project_slug": "autodev-v2",
    }


def mutation_grant_fixture() -> dict[str, object]:
    return {
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
        "artifact_hashes": {"PROJECT.yaml": DIGEST},
        "resource_constraints": {"network": "none"},
        "issued_at": 10,
        "expires_at": 20,
        "revocation_epoch": 0,
        "deployment_epoch": 7,
        "enforcement_backend": "policy-enforced",
        "content_digest": DIGEST,
    }


def approval_receipt_fixture() -> dict[str, object]:
    return {
        "schema_version": 1,
        "receipt_id": "receipt-1",
        "operator_identity": "operator:human",
        "operator_action": "approve-plan",
        "project_id": PROJECT_ID,
        "installation_id": INSTALLATION_ID,
        "artifact_digests": {"docs/plans/AD-01.md": DIGEST},
        "operation_classes": ["write-fixture"],
        "scope": {"paths": ["tests/test_ad01_independent.py"]},
        "issued_at": 10,
        "expires_at": 20,
        "revocation_epoch": 0,
        "deployment_epoch": 7,
        "content_digest": DIGEST,
    }


def validation_receipt_fixture() -> dict[str, object]:
    return {
        "schema_version": 1,
        "gate_id": "gate-1",
        "evidence_class": "LIVE",
        "probe_id": "probe-1",
        "installation_id": INSTALLATION_ID,
        "project_id": PROJECT_ID,
        "invocation_source": "independent-test",
        "observed_at": 10,
        "expires_at": 20,
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


def operation_record_fixture() -> dict[str, object]:
    return {
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
        "operation_state": "ACKNOWLEDGED",
        "native_ids": [],
        "reconciliation_evidence_refs": [],
        "terminal_result": None,
    }


def command_result_fixture() -> dict[str, object]:
    return {
        "schema_version": 1,
        "operation": {"id": "operation-1"},
        "outcome": "NEEDS_INPUT",
        "checks": [],
        "warnings": [],
        "planned_changes": [],
        "applied_changes": [],
        "next_safe_action": "ask-operator",
    }


def configured_project_fixture() -> dict[str, object]:
    return {
        "schema_version": 2,
        "setup_state": "configured",
        "project": {
            "id": PROJECT_ID,
            "slug": "autodev-v2",
            "name": "AutoDev v2",
        },
        "sources": {
            "requirements": ["milestones/AD-01.md"],
            "context": ["context/SHARED-INVARIANTS.md"],
            "discovery": {"roots": ["src", "tests"]},
            "execution_index": "EXECUTION.yaml",
        },
        "execution": {
            "harness": "gajae",
            "workflow": "approved_roadmap_only",
            "base_policy": "dependencies_integrated",
            "target_ref": "main",
            "max_active_milestones": 1,
            "max_primary_actions_per_cycle": 1,
        },
        "verification": {
            "commands": [
                {
                    "id": "unit",
                    "argv": ["python3", "-m", "unittest"],
                    "cwd": ".",
                    "input_paths": ["src", "tests"],
                    "network_policy": "none",
                    "timeout_seconds": 30,
                    "approval_binding": None,
                }
            ],
            "acceptance_sources": ["milestones/AD-01.md"],
            "require_independent_review": True,
        },
        "authority": {"requested": {"write-fixture": "human"}},
    }


def execution_index_fixture() -> dict[str, object]:
    return {
        "schema_version": 2,
        "project_id": PROJECT_ID,
        "milestones": [
            {
                "id": "AD-02",
                "title": "Second milestone appears first",
                "depends_on": ["AD-01"],
                "authority_refs": [
                    {
                        "path": "docs/plans/AD-01.md",
                        "reference": "authority",
                        "digest": DIGEST,
                    }
                ],
                "acceptance_refs": [
                    {
                        "path": "milestones/AD-01.md",
                        "reference": "AD-01-AC1",
                        "digest": DIGEST,
                    }
                ],
                "scope": {
                    "allowed_paths": ["src/autodev/contracts"],
                    "exclusions": [],
                    "prohibited_operations": [],
                },
                "verification_ids": ["unit"],
                "approval": {"state": "proposed", "receipt_ref": None},
                "base_policy": "dependencies_integrated",
                "evidence_refs": [],
            },
            {
                "id": "AD-01",
                "title": "First milestone appears second",
                "depends_on": [],
                "authority_refs": [
                    {
                        "path": "docs/plans/AD-01.md",
                        "reference": "authority",
                        "digest": DIGEST,
                    }
                ],
                "acceptance_refs": [
                    {
                        "path": "milestones/AD-01.md",
                        "reference": "AD-01-AC1",
                        "digest": DIGEST,
                    }
                ],
                "scope": {
                    "allowed_paths": ["src/autodev/contracts"],
                    "exclusions": [],
                    "prohibited_operations": [],
                },
                "verification_ids": ["unit"],
                "approval": {"state": "approved", "receipt_ref": "receipt-1"},
                "base_policy": "dependencies_integrated",
                "evidence_refs": [],
            },
        ],
    }


def readiness_ready_kwargs() -> dict[str, object]:
    return {
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
        "quota_state": "AVAILABLE",
        "execution_state": "IDLE",
        "admission_state": "ALLOW",
        "schedule_state": "UNKNOWN",
    }


VALIDATORS_AND_FIXTURES = (
    (validate_installation_binding, installation_binding_fixture),
    (validate_mutation_grant, mutation_grant_fixture),
    (validate_approval_receipt, approval_receipt_fixture),
    (validate_validation_receipt, validation_receipt_fixture),
    (validate_operation_record, operation_record_fixture),
    (validate_command_result, command_result_fixture),
)

OPTIONAL_OMISSION_FIELDS = {
    "validate_installation_binding": {"project_slug"},
}

NULLABLE_FIELDS = {
    "validate_installation_binding": {"cron_id", "project_slug"},
    "validate_operation_record": {"milestone_id", "terminal_result"},
}


class AD01ParserIndependentTests(unittest.TestCase):
    def assert_parser_issue(
        self,
        document: str,
        *,
        code: str,
        field: str | None = None,
        line: int | None = None,
    ) -> None:
        with self.assertRaises(ContractError) as raised:
            parse_yaml_subset(document, source_name="independent.yaml")
        issue = raised.exception.issues[0]
        self.assertEqual(issue.code, code)
        if field is not None:
            self.assertEqual(issue.field, field)
        if line is not None:
            self.assertEqual(issue.line, line)

    def test_rejects_actual_unsafe_tag_syntax(self) -> None:
        self.assert_parser_issue(
            "schema_version: !secret value\n",
            code="unsafe_syntax",
            field="schema_version",
            line=1,
        )

    def test_rejects_actual_anchor_syntax_before_value_text(self) -> None:
        self.assert_parser_issue(
            "project: &anchor value\n",
            code="unsafe_syntax",
            field="project",
            line=1,
        )

    def test_rejects_actual_alias_syntax(self) -> None:
        self.assert_parser_issue(
            "project: *anchor\n",
            code="unsafe_syntax",
            field="project",
            line=1,
        )

    def test_rejects_merge_key_syntax(self) -> None:
        self.assert_parser_issue(
            "<<: {role: admin}\n",
            code="merge_key",
            field="<<",
            line=1,
        )

    def test_rejects_document_markers(self) -> None:
        self.assert_parser_issue(
            "---\nschema_version: 2\n",
            code="document_marker",
            field="independent.yaml",
            line=1,
        )

    def test_rejects_duplicate_nested_keys_with_source_line(self) -> None:
        self.assert_parser_issue(
            "project:\n  id: one\n  id: two\n",
            code="duplicate_key",
            field="id",
            line=3,
        )

    def test_rejects_duplicate_inline_keys_with_source_line(self) -> None:
        self.assert_parser_issue(
            "project: {id: one, id: two}\n",
            code="duplicate_key",
            field="id",
            line=1,
        )

    def test_rejects_malformed_inline_quote_syntax(self) -> None:
        self.assert_parser_issue(
            'name: "unterminated\n',
            code="malformed_scalar",
            field="name",
            line=1,
        )

    def test_rejects_excessive_inline_nesting(self) -> None:
        nested = "[" * 30 + "value" + "]" * 30
        self.assert_parser_issue(
            f"value: {nested}\n",
            code="excessive_nesting",
            field="value",
            line=1,
        )

    def test_rejects_malformed_inline_collection(self) -> None:
        self.assert_parser_issue(
            "value: [one, two\n",
            code="malformed_inline",
            field="value",
            line=1,
        )

    def test_accepts_safe_literals_that_resemble_yaml_syntax(self) -> None:
        parsed = parse_yaml_subset(
            "\n".join(
                [
                    'bang: "hello!"',
                    'ampersand: "R&D"',
                    'star: "*"',
                    'merge_text: "<<"',
                    'marker_text: "---"',
                    'url: "https://example.test/a?x=1&y=2"',
                    'unicode: "cafe\\u0301"',
                    'path: "fixtures/AD-01/path with spaces.yaml"',
                    "",
                ]
            )
        )
        self.assertEqual(parsed["bang"], "hello!")
        self.assertEqual(parsed["ampersand"], "R&D")
        self.assertEqual(parsed["star"], "*")
        self.assertEqual(parsed["merge_text"], "<<")
        self.assertEqual(parsed["marker_text"], "---")
        self.assertEqual(parsed["url"], "https://example.test/a?x=1&y=2")
        self.assertEqual(parsed["unicode"], "cafe\u0301")
        self.assertEqual(parsed["path"], "fixtures/AD-01/path with spaces.yaml")

    def test_preserves_safe_plain_literals_with_punctuation(self) -> None:
        parsed = parse_yaml_subset(
            "bang: hello!\n"
            "ampersand: R&D\n"
            "url: https://example.test/a?x=1&y=2\n"
            "path: fixtures/AD-01/path with spaces.yaml\n"
        )
        self.assertEqual(parsed["bang"], "hello!")
        self.assertEqual(parsed["ampersand"], "R&D")
        self.assertEqual(parsed["url"], "https://example.test/a?x=1&y=2")
        self.assertEqual(parsed["path"], "fixtures/AD-01/path with spaces.yaml")


class AD01ApprovedSchemaInventoryTests(unittest.TestCase):
    def test_accepts_installation_binding_v1_approved_inventory(self) -> None:
        binding = validate_installation_binding(installation_binding_fixture())
        self.assertEqual(binding.installation_id, INSTALLATION_ID)

    def test_accepts_mutation_grant_v1_approved_inventory(self) -> None:
        grant = validate_mutation_grant(mutation_grant_fixture())
        self.assertEqual(grant.grant_id, "grant-1")

    def test_accepts_approval_receipt_v1_approved_inventory(self) -> None:
        receipt = validate_approval_receipt(approval_receipt_fixture())
        self.assertEqual(receipt.receipt_id, "receipt-1")

    def test_accepts_validation_receipt_v1_approved_inventory(self) -> None:
        receipt = validate_validation_receipt(validation_receipt_fixture())
        self.assertEqual(receipt.gate_id, "gate-1")

    def test_accepts_operation_record_v1_approved_acknowledged_state(self) -> None:
        record = validate_operation_record(operation_record_fixture())
        self.assertEqual(record.operation_state, "ACKNOWLEDGED")

    def test_accepts_command_result_v1_needs_input_outcome(self) -> None:
        result = validate_command_result(command_result_fixture())
        self.assertEqual(result.outcome, "NEEDS_INPUT")


class AD01AdversarialSchemaTests(unittest.TestCase):
    def test_rejects_required_field_omission_for_host_records(self) -> None:
        for validator, fixture_factory in VALIDATORS_AND_FIXTURES:
            record = fixture_factory()
            for field in tuple(record):
                if field in OPTIONAL_OMISSION_FIELDS.get(validator.__name__, set()):
                    continue
                with self.subTest(validator=validator.__name__, field=field):
                    candidate = dict(record)
                    candidate.pop(field)
                    with self.assertRaises(ContractError):
                        validator(candidate)

    def test_rejects_required_field_null_for_host_records(self) -> None:
        for validator, fixture_factory in VALIDATORS_AND_FIXTURES:
            record = fixture_factory()
            for field in tuple(record):
                if field in NULLABLE_FIELDS.get(validator.__name__, set()):
                    continue
                with self.subTest(validator=validator.__name__, field=field):
                    candidate = dict(record)
                    candidate[field] = None
                    with self.assertRaises(ContractError):
                        validator(candidate)

    def test_rejects_required_field_type_mismatch_for_host_records(self) -> None:
        for validator, fixture_factory in VALIDATORS_AND_FIXTURES:
            record = fixture_factory()
            for field, value in tuple(record.items()):
                if value is None:
                    continue
                replacement = "wrong-type" if isinstance(value, (list, dict, bool, int)) else []
                with self.subTest(validator=validator.__name__, field=field):
                    candidate = dict(record)
                    candidate[field] = replacement
                    with self.assertRaises(ContractError):
                        validator(candidate)

    def test_accepts_omitted_optional_project_slug(self) -> None:
        record = installation_binding_fixture()
        record.pop("project_slug")
        binding = validate_installation_binding(record)
        self.assertIsNone(binding.slug)

    def test_accepts_null_operation_milestone_id_and_terminal_result(self) -> None:
        record = operation_record_fixture()
        record["milestone_id"] = None
        record["terminal_result"] = None
        operation = validate_operation_record(record)
        self.assertIsNone(operation.milestone_id)
        self.assertIsNone(operation.terminal_result)

    def test_rejects_boolean_schema_versions_for_v1_records(self) -> None:
        for validator, fixture_factory in VALIDATORS_AND_FIXTURES:
            with self.subTest(validator=validator.__name__):
                record = fixture_factory()
                record["schema_version"] = True
                with self.assertRaises(ContractError):
                    validator(record)

    def test_rejects_bool_for_project_integer_constants(self) -> None:
        project = configured_project_fixture()
        execution = dict(project["execution"])
        execution["max_active_milestones"] = True
        project["execution"] = execution
        with self.assertRaises(ContractError):
            validate_project(project)

    def test_rejects_nested_credential_values_in_host_records(self) -> None:
        record = installation_binding_fixture()
        record["resource_policy"] = {"network": "none", "api_token": "secret-value"}
        with self.assertRaises(ContractError):
            validate_installation_binding(record)

    def test_rejects_empty_mutation_grant_impact(self) -> None:
        record = mutation_grant_fixture()
        record["operator_action"] = ""
        with self.assertRaises(ContractError):
            validate_mutation_grant(record)

    def test_rejects_empty_mutation_grant_artifact_hashes(self) -> None:
        record = mutation_grant_fixture()
        record["artifact_hashes"] = {}
        with self.assertRaises(ContractError):
            validate_mutation_grant(record)

    def test_rejects_empty_approval_receipt_artifact_digests(self) -> None:
        record = approval_receipt_fixture()
        record["artifact_digests"] = {}
        with self.assertRaises(ContractError):
            validate_approval_receipt(record)

    def test_rejects_empty_approval_receipt_operation_classes(self) -> None:
        record = approval_receipt_fixture()
        record["operation_classes"] = []
        with self.assertRaises(ContractError):
            validate_approval_receipt(record)


class AD01PermissionIntersectionTests(unittest.TestCase):
    def test_intersects_four_permission_layers_across_all_81_cases(self) -> None:
        for requested, grant, native, enforcement in product(PERMISSIONS, repeat=4):
            with self.subTest(
                requested=requested,
                grant=grant,
                native=native,
                enforcement=enforcement,
            ):
                result = intersect_permission_layers(
                    {"write-fixture": requested},
                    {"write-fixture": grant},
                    {"write-fixture": native},
                    {"write-fixture": enforcement},
                )
                expected = min(
                    (requested, grant, native, enforcement),
                    key=lambda permission: PERMISSION_RANK[permission],
                )
                self.assertEqual(result, {"write-fixture": expected})


class AD01AuthorityBypassTests(unittest.TestCase):
    def test_context_free_evaluate_authority_does_not_authorize_mutation(self) -> None:
        project = validate_project(configured_project_fixture())
        receipt = validate_approval_receipt(approval_receipt_fixture())
        grant = validate_mutation_grant(mutation_grant_fixture())
        decision = evaluate_authority(
            project=project,
            approval_ref="receipt-1",
            grant_ref="grant-1",
            registry=TrustedRegistry(
                approval_receipts={"receipt-1": receipt},
                mutation_grants={"grant-1": grant},
            ),
            content_hashes={"docs/plans/AD-01.md": DIGEST},
            installation_id=INSTALLATION_ID,
            deployment_epoch=7,
            now=11,
        )
        self.assertFalse(decision.allowed)

    def test_trusted_authority_does_not_fall_back_to_registry_grant_when_context_missing_it(self) -> None:
        project = validate_project(configured_project_fixture())
        receipt = validate_approval_receipt(approval_receipt_fixture())
        grant = validate_mutation_grant(mutation_grant_fixture())
        context = TrustedOperatorContext(
            operator_identity="operator:human",
            now=11,
            project_id=PROJECT_ID,
            installation_id=INSTALLATION_ID,
            profile_identity="profile:local",
            process_generation="process-1",
            deployment_epoch=7,
            source_digests={
                "docs/plans/AD-01.md": DIGEST,
                "PROJECT.yaml": DIGEST,
            },
            revocation_epoch=0,
            operator_grants={},
            native_limits={"write-fixture": "human"},
            enforcement_limits={"write-fixture": "human"},
        )
        decision = evaluate_trusted_authority(
            project=project,
            approval_ref="receipt-1",
            grant_ref="grant-1",
            registry=TrustedRegistry(
                approval_receipts={"receipt-1": receipt},
                mutation_grants={"grant-1": grant},
            ),
            context=context,
            operation_class="write-fixture",
        )
        self.assertFalse(decision.allowed)
        self.assertIn("OPERATOR_GRANT_NOT_IN_TRUSTED_CONTEXT", decision.reason_codes)

    def test_trusted_authority_denies_operation_path_outside_approval_scope(self) -> None:
        project = validate_project(configured_project_fixture())
        receipt = validate_approval_receipt(approval_receipt_fixture())
        grant = validate_mutation_grant(mutation_grant_fixture())
        context = TrustedOperatorContext(
            operator_identity="operator:human",
            now=11,
            project_id=PROJECT_ID,
            installation_id=INSTALLATION_ID,
            profile_identity="profile:local",
            process_generation="process-1",
            deployment_epoch=7,
            source_digests={
                "docs/plans/AD-01.md": DIGEST,
                "PROJECT.yaml": DIGEST,
            },
            revocation_epoch=0,
            operator_grants={"grant-1": grant},
            native_limits={"write-fixture": "human"},
            enforcement_limits={"write-fixture": "human"},
        )
        decision = evaluate_trusted_authority(
            project=project,
            approval_ref="receipt-1",
            grant_ref="grant-1",
            registry=TrustedRegistry(
                approval_receipts={"receipt-1": receipt},
                mutation_grants={"grant-1": grant},
            ),
            context=context,
            operation_class="write-fixture",
            operation_path="src/autodev/contracts/model.py",
        )
        self.assertFalse(decision.allowed)


class AD01ValidationReceiptApplicabilityTests(unittest.TestCase):
    def test_receipt_observed_effects_must_be_within_receipt_allowed_effects(self) -> None:
        receipt = validate_validation_receipt(
            {
                **validation_receipt_fixture(),
                "allowed_effects": [],
                "observed_effects": ["write"],
            }
        )
        ok, reasons = validation_receipt_applicability(
            receipt,
            project_id=PROJECT_ID,
            installation_id=INSTALLATION_ID,
            profile_identity="profile:local",
            process_generation="process-1",
            now=11,
            repo_revision="abc123",
            dirty_fingerprint=OTHER_DIGEST,
            required_hashes={"PROJECT.yaml": DIGEST},
            require_live=True,
            allowed_effects={"write"},
        )
        self.assertFalse(ok)
        self.assertIn("effect_outside_allowed_set", reasons)

    def test_receipt_observed_in_future_is_not_applicable(self) -> None:
        receipt = validate_validation_receipt(
            {
                **validation_receipt_fixture(),
                "observed_at": 999,
                "expires_at": 1000,
            }
        )
        ok, _reasons = validation_receipt_applicability(
            receipt,
            project_id=PROJECT_ID,
            installation_id=INSTALLATION_ID,
            profile_identity="profile:local",
            process_generation="process-1",
            now=10,
            repo_revision="abc123",
            dirty_fingerprint=OTHER_DIGEST,
            required_hashes={"PROJECT.yaml": DIGEST},
            require_live=True,
            allowed_effects=set(),
        )
        self.assertFalse(ok)


class AD01ExecutionReferenceTests(unittest.TestCase):
    def test_execution_refs_use_path_reference_digest_and_allow_non_alphabetical_ids(self) -> None:
        project = validate_project(configured_project_fixture())
        execution = validate_execution(execution_index_fixture(), project)
        self.assertEqual([milestone.id for milestone in execution.milestones], ["AD-02", "AD-01"])
        self.assertEqual(execution.milestones[0].authority_refs[0]["path"], "docs/plans/AD-01.md")
        self.assertEqual(execution.milestones[0].acceptance_refs[0]["reference"], "AD-01-AC1")

    def test_execution_refs_reject_unknown_ref_fields(self) -> None:
        project = validate_project(configured_project_fixture())
        execution = execution_index_fixture()
        first = execution["milestones"][0]
        first["authority_refs"] = [
            {
                "source_path": "docs/plans/AD-01.md",
                "reference": "authority",
                "digest": DIGEST,
            }
        ]
        with self.assertRaises(ContractError) as raised:
            validate_execution(execution, project)
        self.assertEqual(raised.exception.issues[0].code, "unknown_field")

    def test_execution_refs_reject_malformed_ref_digests(self) -> None:
        project = validate_project(configured_project_fixture())
        execution = execution_index_fixture()
        execution["milestones"][0]["acceptance_refs"][0]["digest"] = "not-a-digest"
        with self.assertRaises(ContractError) as raised:
            validate_execution(execution, project)
        self.assertEqual(raised.exception.issues[0].code, "invalid_digest")

    def test_execution_eligibility_denies_stale_digest(self) -> None:
        project = validate_project(configured_project_fixture())
        execution = validate_execution(execution_index_fixture(), project)
        eligibility = evaluate_execution_eligibility(
            execution,
            {
                "docs/plans/AD-01.md": OTHER_DIGEST,
                "milestones/AD-01.md": DIGEST,
            },
        )
        self.assertNotIn("AD-01", eligibility.eligible_ids)
        self.assertIn("CONTENT_DIGEST_STALE", eligibility.reason_codes["AD-01"])

    def test_execution_eligibility_denies_proposed_and_revoked_approval(self) -> None:
        project = validate_project(configured_project_fixture())
        execution_data = execution_index_fixture()
        execution_data["milestones"][1]["approval"] = {"state": "revoked", "receipt_ref": "receipt-1"}
        execution = validate_execution(execution_data, project)
        eligibility = evaluate_execution_eligibility(
            execution,
            {
                "docs/plans/AD-01.md": DIGEST,
                "milestones/AD-01.md": DIGEST,
            },
        )
        self.assertIn("APPROVAL_NOT_APPROVED", eligibility.reason_codes["AD-02"])
        self.assertIn("APPROVAL_NOT_APPROVED", eligibility.reason_codes["AD-01"])

    def test_execution_eligibility_denies_approved_missing_receipt(self) -> None:
        project = validate_project(configured_project_fixture())
        execution_data = execution_index_fixture()
        execution_data["milestones"][1]["approval"] = {"state": "approved", "receipt_ref": None}
        execution = validate_execution(execution_data, project)
        eligibility = evaluate_execution_eligibility(
            execution,
            {
                "docs/plans/AD-01.md": DIGEST,
                "milestones/AD-01.md": DIGEST,
            },
        )
        self.assertNotIn("AD-01", eligibility.eligible_ids)
        self.assertIn("APPROVAL_RECEIPT_MISSING", eligibility.reason_codes["AD-01"])


class AD01MigrationPreviewTests(unittest.TestCase):
    def test_preview_v1_migration_uses_approved_preview_schema(self) -> None:
        preview = preview_v1_migration(
            "project_id: 11111111-1111-1111-1111-111111111111\n"
            "slug: autodev-v2\n"
            "name: AutoDev v2\n"
            "provider_token: secret-looking\n"
        )
        self.assertEqual(preview.schema_version, 1)
        self.assertIn(
            {"path": "provider_token", "type": "str"},
            preview.legacy_fields,
        )
        self.assertEqual(preview.draft_target["schema_version"], 2)
        self.assertFalse(preview.applicable)
        self.assertFalse(preview.writes_performed)
        self.assertIn("provider_token", preview.unresolved_fields)


class AD01IdentityIndependentTests(unittest.TestCase):
    def test_missing_metadata_installation_id_cannot_be_exact_match(self) -> None:
        project = validate_project(configured_project_fixture())
        binding = validate_installation_binding(installation_binding_fixture())
        decision = classify_installation_identity(
            project,
            binding,
            MetadataSnapshot(
                repo_realpath="/workspace/autodev-v2",
                git_common_dir_realpath="/workspace/autodev-v2/.git",
                project_id=PROJECT_ID,
                installation_id=None,
            ),
        )
        self.assertNotEqual(decision.classification, "EXACT_MATCH")


class AD01ParserDiagnosticsTests(unittest.TestCase):
    def test_parser_reports_line_for_unknown_schema_version(self) -> None:
        with self.assertRaises(ContractError) as raised:
            validate_project(
                parse_yaml_subset(
                    "\n"
                    "schema_version: 99\n"
                    "setup_state: configured\n",
                    source_name="PROJECT.yaml",
                )
            )
        issue = raised.exception.issues[0]
        self.assertEqual(issue.field, "schema_version")
        self.assertEqual(issue.code, "unsupported_version")
        self.assertEqual(issue.line, 2)

    def test_parser_reports_location_for_unknown_nested_field(self) -> None:
        document = configured_project_fixture()
        document["project"] = {**document["project"], "unexpected": "value"}
        with self.assertRaises(ContractError) as raised:
            validate_project(document)
        issue = raised.exception.issues[0]
        self.assertEqual(issue.field, "project.unexpected")
        self.assertEqual(issue.code, "unknown_field")
        self.assertIsNotNone(issue.line)


class AD01RecordEnumTests(unittest.TestCase):
    def test_accepts_operation_record_succeeded_state(self) -> None:
        record = operation_record_fixture()
        record["operation_state"] = "SUCCEEDED"
        self.assertEqual(validate_operation_record(record).operation_state, "SUCCEEDED")

    def test_accepts_operation_record_uncertain_state(self) -> None:
        record = operation_record_fixture()
        record["operation_state"] = "UNCERTAIN"
        self.assertEqual(validate_operation_record(record).operation_state, "UNCERTAIN")

    def test_rejects_operation_record_complete_state(self) -> None:
        record = operation_record_fixture()
        record["operation_state"] = "COMPLETE"
        with self.assertRaises(ContractError):
            validate_operation_record(record)

    def test_rejects_operation_record_unknown_state(self) -> None:
        record = operation_record_fixture()
        record["operation_state"] = "UNKNOWN"
        with self.assertRaises(ContractError):
            validate_operation_record(record)

    def test_accepts_command_result_unsupported_outcome(self) -> None:
        result = command_result_fixture()
        result["outcome"] = "UNSUPPORTED"
        self.assertEqual(validate_command_result(result).outcome, "UNSUPPORTED")

    def test_rejects_command_result_blocked_outcome(self) -> None:
        result = command_result_fixture()
        result["outcome"] = "BLOCKED"
        with self.assertRaises(ContractError):
            validate_command_result(result)


class AD01ReadinessIndependentTests(unittest.TestCase):
    def test_deployment_supported_false_reports_unsupported_reason(self) -> None:
        kwargs = readiness_ready_kwargs()
        kwargs["deployment_supported"] = False
        readiness = evaluate_readiness(**kwargs)
        self.assertFalse(readiness.enable_ready)
        self.assertIn("DEPLOYMENT_UNSUPPORTED", readiness.reason_codes)

    def test_unknown_conflict_evidence_denies_with_unknown_reason(self) -> None:
        kwargs = readiness_ready_kwargs()
        kwargs["ownership_conflict"] = None
        readiness = evaluate_readiness(**kwargs)
        self.assertFalse(readiness.enable_ready)
        self.assertIn("CONFLICT_EVIDENCE_UNKNOWN", readiness.reason_codes)

    def test_negative_eligible_milestone_count_denies_dispatch(self) -> None:
        kwargs = readiness_ready_kwargs()
        kwargs["eligible_approved_milestones"] = -1
        readiness = evaluate_readiness(**kwargs)
        self.assertFalse(readiness.dispatch_ready)
        self.assertIn("NO_ELIGIBLE_APPROVED_MILESTONE", readiness.reason_codes)

    def test_boolean_eligible_milestone_count_does_not_dispatch(self) -> None:
        kwargs = readiness_ready_kwargs()
        kwargs["eligible_approved_milestones"] = True
        with self.assertRaises(ValueError):
            evaluate_readiness(**kwargs)


class AD01DirectModelImmutabilityTests(unittest.TestCase):
    def test_direct_project_contract_rejects_direct_field_assignment(self) -> None:
        contract = ProjectContract(
            schema_version=2,
            setup_state="draft",
            project_id=PROJECT_ID,
            slug="autodev-v2",
            name="AutoDev v2",
            sources={},
            execution={},
            verification_commands=(),
            acceptance_sources=(),
            require_independent_review=True,
            requested_authority={},
            raw={},
        )
        with self.assertRaises(FrozenInstanceError):
            contract.name = "changed"

    def test_direct_project_contract_freezes_mutable_nested_containers(self) -> None:
        raw = {"nested": {"items": ["before"]}}
        contract = ProjectContract(
            schema_version=2,
            setup_state="draft",
            project_id=PROJECT_ID,
            slug="autodev-v2",
            name="AutoDev v2",
            sources=raw,
            execution={},
            verification_commands=(),
            acceptance_sources=(),
            require_independent_review=True,
            requested_authority={},
            raw=raw,
        )
        raw["nested"]["items"].append("after")
        self.assertEqual(contract.sources["nested"]["items"], ("before",))

    def test_direct_command_result_freezes_mutable_nested_containers(self) -> None:
        checks = [{"id": "unit", "details": ["before"]}]
        result = CommandResult(
            schema_version=1,
            operation={"id": "operation-1"},
            outcome="PASS",
            checks=checks,
            warnings=[],
            planned_changes=[],
            applied_changes=[],
            next_safe_action="none",
            raw={"checks": checks},
        )
        checks[0]["details"].append("after")
        self.assertEqual(result.checks[0]["details"], ("before",))

    def test_direct_approval_receipt_freezes_mutable_digest_maps(self) -> None:
        content_hashes = {"docs/plans/AD-01.md": DIGEST}
        receipt = ApprovalReceipt(
            schema_version=1,
            receipt_id="receipt-1",
            operator_identity="operator:human",
            installation_id=INSTALLATION_ID,
            project_id=PROJECT_ID,
            content_hashes=content_hashes,
            permission_scope={"write-fixture": "human"},
            deployment_epoch=7,
            expires_at=20,
            revoked_at=0,
            native_limit="human",
            enforcement_limit="human",
        )
        content_hashes["docs/plans/AD-01.md"] = OTHER_DIGEST
        self.assertEqual(receipt.content_hashes["docs/plans/AD-01.md"], DIGEST)


if __name__ == "__main__":
    unittest.main()
