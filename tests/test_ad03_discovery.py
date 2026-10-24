from __future__ import annotations

import hashlib
import json
import os
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from autodev.contracts import load_execution_yaml, load_project_yaml
from autodev.init.discovery import Discovery, categories
from autodev.init.proposal import build_proposal
from autodev.init.render import render_execution, render_project

PROJECT_ID = "e59fd45e-258d-52a6-a0ed-5279249f411e"


class DiscoveryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()

    def put(self, path: str, data: bytes | str):
        target = self.root / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data.encode() if isinstance(data, str) else data)
        return target

    def seed(self, *, path=".agent/PROJECT.yaml", index=".agent/EXECUTION.yaml", context=(), requirements=(), acceptance=(), peer=True):
        data = render_project(PROJECT_ID, "Example", "example", context=context, requirements=requirements,
                              acceptance=acceptance, execution_index=index)
        self.put(path, data)
        if peer:
            self.put(index, render_execution(PROJECT_ID))
        return data

    def codes(self, proposal):
        return {item["code"] for item in proposal.report["diagnostics"]}

    def test_empty_directory_is_deterministic_valid_draft_and_read_only(self):
        first = build_proposal(self.root)
        second = build_proposal(self.root)
        self.assertEqual(first.to_json(), second.to_json())
        self.assertEqual(first.status, "preview")
        self.assertEqual(list(self.root.iterdir()), [])
        ops = {item.path: item for item in first.operations}
        project = load_project_yaml(ops[".agent/PROJECT.yaml"].after)
        execution = load_execution_yaml(ops[".agent/EXECUTION.yaml"].after, project)
        self.assertEqual(project.setup_state, "draft")
        self.assertEqual(execution.milestones, ())
        self.assertEqual(project.requested_authority, {})
        self.assertFalse(first.report["lifecycle_ready"])
        self.assertIsNone(project.execution["target_ref"])
        self.assertEqual(project.verification_commands, ())

    def test_registry_is_finite_and_rejects_fuzzy_artifact_names(self):
        positives = {"AGENT.md": "context", "AGENTS.md": "context", "docs/PRD.md": "requirements",
                     "docs/ROADMAP.yaml": "execution", "docs/plans/p.md": "plans",
                     "ACCEPTANCE-CRITERIA.md": "acceptance", "tests/test_one.py": "tests",
                     "package.json": "metadata"}
        for path, category in positives.items():
            self.assertIn(category, categories(path))
        for path in ("PRODUCT-backup.md", "roadmap-notes.md", "AGENT.sh", "PRD.exe", "my-package.json"):
            self.assertEqual(categories(path), ())

    def test_two_roadmaps_require_an_explicit_choice(self):
        self.put("ROADMAP.md", "one")
        self.put("docs/ROADMAP.yaml", "two")
        ambiguous = build_proposal(self.root)
        self.assertEqual(ambiguous.status, "needs_input")
        self.assertEqual(ambiguous.operations, ())
        self.assertEqual(ambiguous.report["unresolved"][0]["candidates"], ["ROADMAP.md", "docs/ROADMAP.yaml"])
        chosen = build_proposal(self.root, selections=("execution=docs/ROADMAP.yaml",))
        self.assertEqual(chosen.status, "preview")
        self.assertEqual(chosen.report["selected"]["execution"], ["docs/ROADMAP.yaml"])

    def test_context_authority_is_not_implicitly_joined(self):
        self.put("AGENT.md", "singular")
        self.put("AGENTS.md", "plural")
        self.assertEqual(build_proposal(self.root).status, "needs_input")
        chosen = build_proposal(self.root, selections=("context=AGENT.md", "context=AGENTS.md"))
        project = load_project_yaml(next(op.after for op in chosen.operations if op.path.endswith("PROJECT.yaml")))
        self.assertEqual(tuple(project.sources["context"]), ("AGENT.md", "AGENTS.md"))

    def test_declared_context_is_really_read_without_runtime_claim(self):
        self.seed(context=("AGENT.md", "AGENTS.md"))
        bodies = {"AGENT.md": b"singular\r\n", "AGENTS.md": "plural unicode é".encode()}
        for path, body in bodies.items():
            self.put(path, body)
        proposal = build_proposal(self.root)
        self.assertEqual(proposal.status, "noop")
        reads = proposal.report["declared_context"]
        self.assertEqual({item["path"] for item in reads}, set(bodies))
        for item in reads:
            self.assertEqual(item["sha256"], hashlib.sha256(bodies[item["path"]]).hexdigest())
            self.assertEqual(item["status"], "declared_context_read")
            self.assertEqual(item["runtime_ingestion"], "unverified")

    def test_missing_declared_context_requirement_or_acceptance_never_falls_back(self):
        for field in ("context", "requirements", "acceptance"):
            with self.subTest(field=field):
                self.seed(**{field: ("missing.md",)})
                self.put("PRODUCT.md", "replacement")
                proposal = build_proposal(self.root)
                self.assertEqual(proposal.status, "needs_input")
                self.assertEqual(proposal.operations, ())
                self.assertIn("missing_reference", self.codes(proposal))

    def test_existing_explicit_reference_wins_and_override_is_refused(self):
        self.seed(requirements=("selected.md",))
        self.put("selected.md", "chosen")
        self.put("PRODUCT.md", "other")
        self.put("docs/PRD.md", "another")
        proposal = build_proposal(self.root)
        self.assertEqual(proposal.status, "noop")
        self.assertEqual(proposal.report["selected"]["requirements"], ["selected.md"])
        override = build_proposal(self.root, selections=("requirements=PRODUCT.md",))
        self.assertIn("existing_reference_immutable", self.codes(override))

    def test_missing_declared_index_is_created_at_exact_path_and_keeps_identity(self):
        original = self.seed(index="indices/chosen.yaml", peer=False)
        proposal = build_proposal(self.root)
        self.assertEqual([item.path for item in proposal.operations], ["indices/chosen.yaml"])
        self.assertEqual((self.root / ".agent/PROJECT.yaml").read_bytes(), original)
        self.assertIn(PROJECT_ID.encode(), proposal.operations[0].after)

    def test_existing_execution_seeds_missing_project_uuid(self):
        self.put(".agent/EXECUTION.yaml", render_execution(PROJECT_ID))
        proposal = build_proposal(self.root)
        self.assertEqual([item.path for item in proposal.operations], [".agent/PROJECT.yaml"])
        self.assertEqual(load_project_yaml(proposal.operations[0].after).project_id, PROJECT_ID)

    def test_malformed_or_mismatched_contracts_never_get_rewritten(self):
        for path, body in ((".agent/PROJECT.yaml", b"schema_version: 2\n"),
                           (".agent/EXECUTION.yaml", b"schema_version: 2\nproject_id: bad\n")):
            with self.subTest(path=path):
                self.seed()
                self.put(path, body)
                proposal = build_proposal(self.root)
                self.assertEqual(proposal.status, "needs_input")
                self.assertEqual(proposal.operations, ())
                self.assertEqual((self.root / path).read_bytes(), body)

    def test_conventional_root_project_is_reused_without_duplicate(self):
        self.seed(path="PROJECT.yaml")
        proposal = build_proposal(self.root)
        self.assertEqual(proposal.status, "noop")
        self.assertEqual(proposal.report["project_path"], "PROJECT.yaml")
        self.assertFalse((self.root / ".agent/PROJECT.yaml").exists())

    def test_two_conventional_projects_require_project_choice(self):
        data = self.seed()
        self.put("PROJECT.yaml", data)
        ambiguous = build_proposal(self.root)
        self.assertIn("multiple_projects", self.codes(ambiguous))
        self.assertEqual(ambiguous.status, "needs_input")
        self.assertEqual(build_proposal(self.root, project="PROJECT.yaml").status, "noop")

    def test_custom_project_is_created_only_without_competing_identity(self):
        proposal = build_proposal(self.root, project="config/custom.yaml")
        self.assertIn("config/custom.yaml", [item.path for item in proposal.operations])
        self.seed()
        conflict = build_proposal(self.root, project="config/custom.yaml")
        self.assertIn("project_identity_conflict", self.codes(conflict))

    def test_display_metadata_is_explicit_and_existing_metadata_is_immutable(self):
        proposal = build_proposal(self.root, name="Café project", slug="cafe")
        contract = load_project_yaml(next(item.after for item in proposal.operations if item.path.endswith("PROJECT.yaml")))
        self.assertEqual((contract.name, contract.slug), ("Café project", "cafe"))
        self.assertEqual(build_proposal(self.root, slug="INVALID").status, "needs_input")
        self.assertEqual(build_proposal(self.root, name="").status, "needs_input")
        self.seed()
        self.assertIn("existing_project_metadata_immutable", self.codes(build_proposal(self.root, name="Changed")))

    def test_existing_crlf_comments_quotes_unicode_and_no_final_newline_stay_exact(self):
        original = self.seed()
        original = b"# user comment\r\n" + original.replace(b"\n", b"\r\n").rstrip(b"\r\n")
        self.put(".agent/PROJECT.yaml", original)
        self.put(".agent/EXECUTION.yaml", b"# execution\r\n" + render_execution(PROJECT_ID).replace(b"\n", b"\r\n").rstrip(b"\r\n"))
        before = {str(path.relative_to(self.root)): path.read_bytes() for path in self.root.rglob("*") if path.is_file()}
        proposal = build_proposal(self.root)
        self.assertEqual(proposal.status, "noop")
        self.assertEqual(proposal.operations, ())
        self.assertEqual(before, {str(path.relative_to(self.root)): path.read_bytes() for path in self.root.rglob("*") if path.is_file()})

    def test_existing_configured_contract_gets_only_missing_empty_index(self):
        fixture = Path(__file__).resolve().parents[1] / "fixtures/AD-01/project-configured.yaml"
        original = fixture.read_bytes()
        self.put(".agent/PROJECT.yaml", original)
        self.put("milestones/AD-01.md", "authoritative requirements and acceptance")
        self.put("context/SHARED-INVARIANTS.md", "context")
        (self.root / "src").mkdir()
        (self.root / "tests").mkdir()
        proposal = build_proposal(self.root)
        self.assertEqual(proposal.status, "preview")
        self.assertEqual(proposal.report["setup_state"], "configured")
        self.assertFalse(proposal.report["lifecycle_ready"])
        self.assertEqual([item.path for item in proposal.operations], [".agent/EXECUTION.yaml"])
        self.assertEqual((self.root / ".agent/PROJECT.yaml").read_bytes(), original)

    def test_explicit_repository_discovery_root_is_supported(self):
        original = self.seed()
        original = original.replace(b"    roots: []", b"    roots:\n      - '.'")
        self.put(".agent/PROJECT.yaml", original)
        self.put("custom/PRODUCT.md", "explicitly discoverable")
        proposal = build_proposal(self.root)
        self.assertEqual(proposal.status, "noop")
        self.assertEqual(proposal.report["candidates"]["requirements"], ["custom/PRODUCT.md"])

    def test_new_competing_candidate_and_changed_reference_change_digest(self):
        self.put("ROADMAP.md", "first")
        before = build_proposal(self.root)
        self.put("docs/ROADMAP.md", "second")
        self.assertNotEqual(before.digest, build_proposal(self.root).digest)
        self.seed(context=("readme.txt",))
        self.put("readme.txt", "first")
        first = build_proposal(self.root, selections=("execution=ROADMAP.md",))
        self.put("readme.txt", "edited")
        self.assertNotEqual(first.digest, build_proposal(self.root, selections=("execution=ROADMAP.md",)).digest)

    def test_streaming_enumeration_stops_at_shared_cap(self):
        for number in range(12):
            self.put(f"unrelated-{number}", "x")
        with patch("autodev.init.discovery.MAX_ENTRIES", 5):
            proposal = build_proposal(self.root)
        self.assertIn("discovery_limit", self.codes(proposal))
        self.assertEqual(proposal.status, "needs_input")
        self.assertLessEqual(proposal.report["discovery"]["entries"], 6)

    def test_skipped_entries_are_counted_without_buffering_past_limit(self):
        self.put("node_modules/canary", "never read")
        self.put("dist/canary", "never read")
        with patch("autodev.init.discovery.MAX_ENTRIES", 1):
            proposal = build_proposal(self.root)
        self.assertIn("discovery_limit", self.codes(proposal))
        self.assertEqual(proposal.report["discovery"]["content_bytes"], 0)

    def test_candidate_per_file_and_aggregate_bounds(self):
        self.put("PRODUCT.md", "one")
        self.put("AGENTS.md", "two")
        for constant, limit in (("MAX_CANDIDATES", 1), ("MAX_TOTAL_BYTES", 2)):
            with self.subTest(constant=constant), patch("autodev.init.discovery." + constant, limit):
                self.assertEqual(build_proposal(self.root).status, "needs_input")
        with patch("autodev.init.discovery.MAX_FILE_BYTES", 2):
            proposal = build_proposal(self.root)
        self.assertIn("file_read_limit", self.codes(proposal))

    def test_depth_limit_with_exact_selection_beyond_depth(self):
        self.put("docs/a/b/c/PRODUCT.md", "within")
        self.put("docs/a/b/c/d/PRD.md", "beyond")
        proposal = build_proposal(self.root)
        self.assertEqual(proposal.report["candidates"]["requirements"], ["docs/a/b/c/PRODUCT.md"])
        selected = build_proposal(self.root, selections=("requirements=docs/a/b/c/d/PRD.md",))
        self.assertEqual(selected.report["selected"]["requirements"], ["docs/a/b/c/d/PRD.md"])

    def test_invalid_paths_symlinks_hardlinks_and_special_files_are_rejected(self):
        self.assertEqual(build_proposal(self.root, project="../escape.yaml").status, "needs_input")
        self.put("source", "x")
        (self.root / "linked").symlink_to(self.root / "source")
        self.assertIn("symlink_path", self.codes(build_proposal(self.root, project="linked")))
        os.link(self.root / "source", self.root / "hardlink")
        self.assertIn("hardlinked_target", self.codes(build_proposal(self.root, project="hardlink")))
        os.mkfifo(self.root / "PRODUCT.md")
        self.assertIn("non_regular_file", self.codes(build_proposal(self.root)))

    def test_casefold_collision_and_custom_parent_collision_block(self):
        self.put("docs/PRODUCT.md", "first")
        self.assertIn("casefold_collision", self.codes(build_proposal(self.root, selections=("requirements=docs/product.md",))))
        self.put("CONFIG/placeholder", "x")
        self.assertIn("casefold_collision", self.codes(build_proposal(self.root, project="config/custom.yaml")))

    def test_explicit_references_share_candidate_budget(self):
        for number in range(4):
            self.put(f"explicit-{number}.txt", "")
        with patch("autodev.init.discovery.MAX_CANDIDATES", 3):
            proposal = build_proposal(self.root, selections=tuple(f"context=explicit-{number}.txt" for number in range(4)))
        self.assertEqual(proposal.status, "needs_input")
        self.assertIn("discovery_limit", self.codes(proposal))

    def test_ancestor_swap_during_read_cannot_follow_outside_symlink(self):
        self.put("docs/secret.txt", "inside")
        outside = tempfile.TemporaryDirectory()
        self.addCleanup(outside.cleanup)
        outside_root = Path(outside.name).resolve()
        (outside_root / "secret.txt").write_text("outside secret")
        real_open = os.open
        swapped = False

        def opening(path, flags, *args, **kwargs):
            nonlocal swapped
            if path == "docs" and kwargs.get("dir_fd") is not None and not swapped:
                swapped = True
                (self.root / "docs").rename(self.root / "old-docs")
                (self.root / "docs").symlink_to(outside_root, target_is_directory=True)
            return real_open(path, flags, *args, **kwargs)

        discovery = Discovery(self.root)
        with patch("autodev.init.discovery.os.open", side_effect=opening):
            self.assertIsNone(discovery.read("docs/secret.txt", required=True))
        self.assertTrue(swapped)
        self.assertNotIn("outside secret", str(discovery.contents))

    def test_renderer_preserves_unicode_quotes_and_literal_path_characters(self):
        body = render_project(PROJECT_ID, "O'Brien, café # example", "example", context=("space /café's.md",))
        contract = load_project_yaml(body)
        self.assertEqual(contract.name, "O'Brien, café # example")
        self.assertEqual(tuple(contract.sources["context"]), ("space /café's.md",))

    def test_bootstrap_container_is_not_a_bound_change(self):
        before = build_proposal(self.root)
        (self.root / ".agent").mkdir()
        after = build_proposal(self.root)
        self.assertEqual(before.digest, after.digest)

    def test_recovery_status_and_bootstrap_blocker_remain_distinct(self):
        for recovery_status, expected in (("recovery_required", "recovery_required"),
                                          ("bootstrap_recovery_required", "needs_input")):
            with self.subTest(recovery_status=recovery_status), patch("autodev.init.apply.inspect_recovery", return_value={
                "status": recovery_status, "diagnostics": [], "operations": []
            }):
                proposal = build_proposal(self.root)
                self.assertEqual(proposal.status, expected)
                self.assertEqual(proposal.operations, ())
                self.assertIn(recovery_status, self.codes(proposal))

    def test_metadata_is_passive_and_malformed_data_is_reported(self):
        fixture = Path(__file__).resolve().parents[1] / "fixtures/AD-03/hostile-metadata"
        shutil.copytree(fixture, self.root, dirs_exist_ok=True)
        proposal = build_proposal(self.root)
        self.assertFalse((self.root / "AUTODEV_MUST_NOT_EXECUTE").exists())
        self.assertEqual(proposal.status, "preview")
        self.put("package.json", "{broken")
        self.assertIn("malformed_metadata", self.codes(build_proposal(self.root)))

    def test_hidden_context_requires_explicit_reference(self):
        self.put(".hidden/AGENTS.md", "hidden")
        first = build_proposal(self.root)
        self.assertEqual(first.report["candidates"]["context"], [])
        selected = build_proposal(self.root, selections=("context=.hidden/AGENTS.md",))
        self.assertEqual(selected.report["selected"]["context"], [".hidden/AGENTS.md"])

    def test_public_append_preview_excludes_original_source_body(self):
        from autodev.init.proposal import FileOperation
        original = b"# user private commentary\nsecret_token=do-not-display\n"
        operation = FileOperation(".gitignore", original, original + b"/managed/\n")
        displayed = operation.to_dict()
        self.assertNotIn("proposed_text", displayed)
        self.assertEqual(displayed["appended_text"], "/managed/\n")
        self.assertNotIn("do-not-display", json.dumps(displayed))

    def test_public_new_contract_preview_redacts_without_changing_exact_bytes(self):
        proposal = build_proposal(self.root, name="token=private-value", slug="example")
        self.assertNotIn("private-value", proposal.to_json())
        self.assertIn(b"private-value", next(item.after for item in proposal.operations if item.path.endswith("PROJECT.yaml")))

    def test_public_report_is_a_fresh_tree(self):
        proposal = build_proposal(self.root)
        stored = json.dumps(proposal.report, sort_keys=True)
        expected = proposal.to_json()
        displayed = proposal.to_dict()
        displayed["candidates"]["context"].append("external.md")
        displayed["operations"][0]["path"] = "external.yaml"
        self.assertEqual(json.dumps(proposal.report, sort_keys=True), stored)
        self.assertEqual(proposal.to_json(), expected)


if __name__ == "__main__":
    unittest.main()
