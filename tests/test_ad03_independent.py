"""Independent AD-03 acceptance and adversarial checks using real files/processes."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

from autodev.contracts import load_execution_yaml, load_project_yaml
from autodev.init.apply import apply_proposal, inspect_recovery, recover_repository
from autodev.init.proposal import build_proposal
from autodev.init.render import render_execution, render_project


ROOT = Path(__file__).resolve().parents[1]
PROJECT_ID = "11111111-1111-1111-1111-111111111111"
ENV = {"PATH": "/usr/bin:/bin", "PYTHONPATH": str(ROOT / "src"),
       "PYTHONDONTWRITEBYTECODE": "1"}


def file_audit(root: Path) -> dict:
    """Hash plus inode/mode/time catches rewrite of identical bytes too."""
    result = {}
    for path in sorted(root.rglob("*")):
        if path.is_file() and not path.is_symlink():
            info = path.stat()
            result[path.relative_to(root).as_posix()] = (
                hashlib.sha256(path.read_bytes()).hexdigest(), info.st_dev, info.st_ino,
                info.st_mode, info.st_mtime_ns)
    return result


class IndependentInitTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(dir="/private/tmp")
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.repo = self.base / "-- dépôt with spaces"
        self.repo.mkdir()

    def cli(self, *flags):
        result = subprocess.run([sys.executable, "-B", "-m", "autodev", "init",
                                 str(self.repo), *flags], cwd=ROOT, env=ENV,
                                capture_output=True, text=True, timeout=30)
        return result, json.loads(result.stdout)

    def python(self, script, *args):
        return subprocess.run([sys.executable, "-B", "-c", script, *map(str, args)],
                              cwd=ROOT, env=ENV, capture_output=True, text=True, timeout=30)

    def git(self, *args):
        result = subprocess.run(["git", "-C", str(self.repo), *args], env=ENV,
                                capture_output=True, text=True, timeout=20)
        self.assertEqual(result.returncode, 0, result.stderr)
        return result.stdout

    def contracts(self, *, context=(), index=".agent/EXECUTION.yaml", newline=b"\n", final=True):
        (self.repo / ".agent").mkdir(exist_ok=True)
        project = render_project(PROJECT_ID, "Existing dépôt", "existing", context=context,
                                 execution_index=index)
        project = b"# keep this comment exactly\n" + project
        project = project.replace(b"\n", newline)
        if not final:
            project = project[:-len(newline)]
        (self.repo / ".agent/PROJECT.yaml").write_bytes(project)
        index_path = self.repo / index
        index_path.parent.mkdir(parents=True, exist_ok=True)
        index_path.write_bytes(render_execution(PROJECT_ID).replace(b"\n", newline))

    def test_empty_preview_draft_apply_and_noop_have_exact_effect_scope(self):
        preview, report = self.cli("--json", "--dry-run")
        self.assertEqual(preview.returncode, 0, preview.stderr)
        self.assertEqual(list(self.repo.iterdir()), [])
        self.assertFalse(report["lifecycle_ready"])
        applied, envelope = self.cli("--json", "--apply", report["digest"], "--yes")
        self.assertEqual(applied.returncode, 0, applied.stdout + applied.stderr)
        self.assertEqual(envelope["status"], "applied")
        project = load_project_yaml((self.repo / ".agent/PROJECT.yaml").read_bytes())
        execution = load_execution_yaml((self.repo / ".agent/EXECUTION.yaml").read_bytes(), project)
        self.assertEqual(project.setup_state, "draft")
        self.assertEqual(execution.milestones, ())
        self.assertEqual(project.requested_authority, {})
        files = file_audit(self.repo)
        self.assertTrue(all(path in {".agent/PROJECT.yaml", ".agent/EXECUTION.yaml"}
                            or path.startswith(".agent/.init-state/") for path in files), files)
        noop, second = self.cli("--json")
        self.assertEqual(noop.returncode, 0, noop.stderr)
        self.assertEqual(second["status"], "noop")
        self.assertEqual(files, file_audit(self.repo))

    def test_crlf_comments_unicode_and_no_final_newline_are_never_rewritten(self):
        self.contracts(newline=b"\r\n", final=False)
        before = file_audit(self.repo)
        for flags in (("--json",), ("--dry-run", "--json"), ("--yes",)):
            process = subprocess.run([sys.executable, "-B", "-m", "autodev", "init", str(self.repo), *flags],
                                     cwd=ROOT, env=ENV, capture_output=True, text=True, timeout=30)
            self.assertEqual(process.returncode, 0, process.stdout + process.stderr)
            self.assertEqual(before, file_audit(self.repo))
        self.assertFalse((self.repo / ".agent/.init-state").exists())

    def test_competing_roadmaps_fail_closed_and_explicit_selection_binds(self):
        (self.repo / "ROADMAP.md").write_bytes(b"# first\n")
        (self.repo / "docs").mkdir()
        (self.repo / "docs/ROADMAP.md").write_bytes(b"# second\n")
        before = file_audit(self.repo)
        result, report = self.cli("--json")
        self.assertEqual(result.returncode, 2)
        self.assertEqual(report["status"], "needs_input")
        candidates = next(item["candidates"] for item in report["unresolved"] if item["category"] == "execution")
        self.assertEqual(candidates, ["ROADMAP.md", "docs/ROADMAP.md"])
        selected, choice = self.cli("--json", "--select", "execution=docs/ROADMAP.md")
        self.assertEqual(selected.returncode, 0, selected.stdout + selected.stderr)
        self.assertEqual(before, file_audit(self.repo))
        self.assertNotEqual(report["digest"], choice["digest"])

    def test_each_declared_context_has_real_bytes_hash_and_unverified_runtime(self):
        content = {"AGENT.md": b"# singular context\n", "AGENTS.md": "# plural café\n".encode()}
        for path, data in content.items():
            (self.repo / path).write_bytes(data)
        self.contracts(context=tuple(content))
        before = file_audit(self.repo)
        result, report = self.cli("--json")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        serialized = json.dumps(report)
        for path, data in content.items():
            self.assertIn(path, serialized)
            self.assertIn(hashlib.sha256(data).hexdigest(), serialized)
        self.assertIn("declared_context_read", serialized)
        self.assertIn('"runtime_ingestion": "unverified"', serialized)
        self.assertEqual(before, file_audit(self.repo))

    def test_declared_missing_context_never_falls_back_to_other_context(self):
        self.contracts(context=("missing/AGENT.md",))
        (self.repo / "AGENTS.md").write_bytes(b"# must not substitute\n")
        before = file_audit(self.repo)
        result, report = self.cli("--json")
        self.assertEqual(result.returncode, 2)
        self.assertEqual(report["status"], "needs_input")
        self.assertIn("missing/AGENT.md", json.dumps(report))
        self.assertEqual(before, file_audit(self.repo))

    def test_changed_declared_reference_invalidates_review_before_bootstrap(self):
        (self.repo / "AGENT.md").write_bytes(b"# original\n")
        self.contracts(context=("AGENT.md",), index="records/execution.yaml")
        (self.repo / "records/execution.yaml").unlink()
        preview, report = self.cli("--json")
        self.assertEqual(preview.returncode, 0, preview.stdout + preview.stderr)
        (self.repo / "AGENT.md").write_bytes(b"# changed\n")
        before = file_audit(self.repo)
        stale, envelope = self.cli("--json", "--apply", report["digest"], "--yes")
        self.assertNotEqual(stale.returncode, 0)
        self.assertEqual(envelope["status"], "stale_proposal")
        self.assertEqual(before, file_audit(self.repo))
        self.assertFalse((self.repo / ".agent/.init-state").exists())

    def test_missing_declared_index_creates_exact_destination_and_keeps_project(self):
        self.contracts(index="records/execution.yaml")
        (self.repo / "records/execution.yaml").unlink()
        original = (self.repo / ".agent/PROJECT.yaml").read_bytes()
        preview, report = self.cli("--json")
        self.assertEqual(preview.returncode, 0, preview.stdout + preview.stderr)
        result, outcome = self.cli("--json", "--apply", report["digest"], "--yes")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual((self.repo / ".agent/PROJECT.yaml").read_bytes(), original)
        self.assertFalse((self.repo / ".agent/EXECUTION.yaml").exists())
        self.assertEqual((self.repo / "records/execution.yaml").read_bytes(), render_execution(PROJECT_ID))

    def test_multiple_project_locations_require_explicit_reconciliation(self):
        self.contracts()
        (self.repo / "PROJECT.yaml").write_bytes((self.repo / ".agent/PROJECT.yaml").read_bytes())
        before = file_audit(self.repo)
        result, report = self.cli("--json")
        self.assertEqual(result.returncode, 2)
        self.assertIn("multiple_projects", json.dumps(report))
        self.assertEqual(before, file_audit(self.repo))
        (self.repo / "custom.yaml").write_bytes(render_project(
            "22222222-2222-2222-2222-222222222222", "Other", "other"))
        before = file_audit(self.repo)
        result, report = self.cli("--json", "--project", "custom.yaml")
        self.assertEqual(result.returncode, 2)
        self.assertIn("project_identity_conflict", json.dumps(report))
        self.assertEqual(before, file_audit(self.repo))

    def test_unborn_git_then_tracked_deleted_bucket_blocks_without_index_mutation(self):
        self.git("init", "-q")
        safe, report = self.cli("--json")
        self.assertEqual(safe.returncode, 0, safe.stdout + safe.stderr)
        self.assertFalse(report["lifecycle_ready"])
        (self.repo / "worktrees").mkdir()
        (self.repo / "worktrees/user.txt").write_bytes(b"indexed user bytes")
        self.git("add", "--", "worktrees/user.txt")
        (self.repo / "worktrees/user.txt").unlink()
        before = file_audit(self.repo)
        blocked, report = self.cli("--json", "--worktree-bucket", "worktrees")
        self.assertEqual(blocked.returncode, 2, blocked.stdout + blocked.stderr)
        self.assertIn("worktrees/user.txt", json.dumps(report))
        self.assertEqual(before, file_audit(self.repo))
        self.assertFalse((self.repo / ".gitignore").exists())

    def test_real_ignore_append_preserves_prefix_mode_and_git_index(self):
        self.git("init", "-q")
        original = b"# preserve CRLF\r\n!important.txt"
        ignore = self.repo / ".gitignore"
        ignore.write_bytes(original)
        ignore.chmod(0o640)
        before_git = file_audit(self.repo / ".git")
        result, preview = self.cli("--json", "--worktree-bucket", "worktrees")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        applied, envelope = self.cli("--json", "--worktree-bucket", "worktrees", "--apply", preview["digest"], "--yes")
        self.assertEqual(applied.returncode, 0, applied.stdout + applied.stderr)
        self.assertEqual(envelope["status"], "applied")
        self.assertTrue(ignore.read_bytes().startswith(original))
        self.assertEqual(ignore.stat().st_mode & 0o777, 0o640)
        self.assertEqual(before_git, file_audit(self.repo / ".git"))
        self.assertEqual(self.git("check-ignore", "--no-index", "--", "worktrees/nested/file.txt").strip(), "worktrees/nested/file.txt")

    def test_hostile_metadata_and_hook_remain_inert_in_preview_and_apply(self):
        canary = self.base / "PROJECT_CODE_EXECUTED"
        (self.repo / "package.json").write_text(json.dumps({"scripts": {"prepare": "touch " + str(canary)}}))
        (self.repo / "Makefile").write_text("all:\n\ttouch " + str(canary) + "\n")
        (self.repo / ".envrc").write_text("touch " + str(canary) + "\n")
        self.git("init", "-q")
        hook = self.repo / ".git/hooks/post-checkout"
        hook.write_text("#!/bin/sh\ntouch '" + str(canary) + "'\n")
        hook.chmod(0o755)
        before = file_audit(self.repo)
        result, report = self.cli("--json", "--dry-run")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(before, file_audit(self.repo))
        result, report = self.cli("--json", "--apply", report["digest"], "--yes")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertFalse(canary.exists())
        after = file_audit(self.repo)
        for path, values in before.items():
            self.assertEqual(values, after[path], path)

    def test_symlink_root_and_foreign_state_fail_without_alignment_writes(self):
        alias = self.base / "alias"
        alias.symlink_to(self.repo, target_is_directory=True)
        self.assertEqual(build_proposal(alias).status, "needs_input")
        state = self.repo / ".agent/.init-state"
        state.mkdir(parents=True, mode=0o700)
        before = file_audit(self.repo)
        result, report = self.cli("--json")
        self.assertEqual(result.returncode, 2)
        self.assertIn("bootstrap_recovery_required", json.dumps(report))
        self.assertEqual(before, file_audit(self.repo))
        self.assertFalse((self.repo / ".agent/PROJECT.yaml").exists())

    def test_absent_target_race_never_clobbers_user_creation(self):
        proposal = build_proposal(self.repo)
        created = []
        def race(label, path):
            if label == "before_publish" and not created:
                target = self.repo / path
                target.write_bytes(b"external user file")
                created.append(target)
        result = apply_proposal(proposal, expected_digest=proposal.digest, checkpoint=race)
        self.assertEqual(result.status, "recovery_required", result)
        self.assertEqual(created[0].read_bytes(), b"external user file")
        self.assertEqual(recover_repository(self.repo).status, "recovery_required")
        self.assertEqual(created[0].read_bytes(), b"external user file")

    def test_same_bytes_new_inode_survives_rollback(self):
        proposal = build_proposal(self.repo)
        replaced = []
        def race(label, path):
            if label == "after_publish" and not replaced:
                target = self.repo / path
                other = self.base / "replacement"
                other.write_bytes(target.read_bytes())
                os.replace(other, target)
                replaced.append((target, target.stat().st_ino, target.read_bytes()))
                raise RuntimeError("independent external inode replacement")
        result = apply_proposal(proposal, expected_digest=proposal.digest, checkpoint=race)
        self.assertEqual(result.status, "recovery_required", result)
        target, inode, content = replaced[0]
        self.assertEqual((target.stat().st_ino, target.read_bytes()), (inode, content))
        self.assertEqual(recover_repository(self.repo).status, "recovery_required")
        self.assertEqual((target.stat().st_ino, target.read_bytes()), (inode, content))

    def test_changed_staging_bytes_are_rejected_before_target_publication(self):
        proposal = build_proposal(self.repo)
        attacked = []
        published = []
        def tamper(label, path):
            if label == "before_publish" and not attacked:
                record = json.loads((self.repo / ".agent/.init-state/transaction.json").read_bytes())
                operation = next(item for item in record["operations"] if item["path"] == path)
                (self.repo / operation["staging"]).write_bytes(b"external staging corruption")
                attacked.append(path)
            if label == "after_publish":
                published.append(path)
        result = apply_proposal(proposal, expected_digest=proposal.digest, checkpoint=tamper)
        self.assertTrue(attacked, "fault did not reach staged bytes")
        self.assertNotEqual(result.status, "applied", result)
        self.assertNotIn(attacked[0], published, "unreviewed staging bytes reached alignment destination")
        self.assertFalse((self.repo / attacked[0]).exists(), result)

    def test_bootstrap_parent_symlink_swap_never_creates_external_state(self):
        outside = self.base / "bootstrap-outside"
        outside.mkdir()
        proposal = build_proposal(self.repo)
        original_mkdir = os.mkdir
        swapped = []
        def swap_then_mkdir(path, *args, **kwargs):
            if not swapped and str(path).rstrip("/").split("/")[-1] == ".init-state":
                (self.repo / ".agent").rename(self.repo / "moved-agent")
                (self.repo / ".agent").symlink_to(outside, target_is_directory=True)
                swapped.append(True)
            return original_mkdir(path, *args, **kwargs)
        with patch("os.mkdir", side_effect=swap_then_mkdir):
            result = apply_proposal(proposal, expected_digest=proposal.digest)
        self.assertTrue(swapped, "fault did not reach bootstrap mkdir")
        self.assertEqual(list(outside.iterdir()), [], "private state escaped through changed .agent parent")
        self.assertNotEqual(result.status, "applied", result)

    def test_process_death_at_durable_boundaries_reconciles_without_replay(self):
        script = """import os,sys
from autodev.init.proposal import build_proposal
from autodev.init.apply import apply_proposal
p=build_proposal(sys.argv[1])
def stop(label,path):
 if label==sys.argv[2]: os._exit(79)
apply_proposal(p,expected_digest=p.digest,checkpoint=stop)
raise SystemExit(9)
"""
        for boundary in ("bootstrap_directory", "after_intent", "before_publish", "after_publish",
                         "after_checkpoint", "before_commit", "after_commit"):
            with self.subTest(boundary=boundary):
                repo = self.base / boundary
                repo.mkdir()
                crashed = self.python(script, repo, boundary)
                self.assertEqual(crashed.returncode, 79, crashed.stdout + crashed.stderr)
                state = inspect_recovery(repo)
                if boundary == "bootstrap_directory":
                    self.assertEqual(state["status"], "bootstrap_recovery_required")
                elif boundary == "after_commit":
                    self.assertEqual(state["status"], "clean")
                    self.assertTrue((repo / ".agent/PROJECT.yaml").is_file())
                else:
                    self.assertEqual(state["status"], "recovery_required", state)
                    recovered = self.python("import json,sys; from autodev.init.apply import recover_repository; print(json.dumps(recover_repository(sys.argv[1]).to_dict()))", repo)
                    self.assertEqual(recovered.returncode, 0, recovered.stderr)
                    self.assertEqual(json.loads(recovered.stdout)["status"], "recovered")
                    self.assertFalse((repo / ".agent/PROJECT.yaml").exists())
                    self.assertFalse((repo / ".agent/EXECUTION.yaml").exists())
                    self.assertEqual(inspect_recovery(repo)["status"], "clean")

    def test_process_death_between_stage_creation_and_manifest_cannot_claim_clean_orphan(self):
        script = """import os,sys
import autodev.init.apply as transaction
from autodev.init.proposal import build_proposal
original=transaction.stage
def crash(*args,**kwargs):
 original(*args,**kwargs)
 os._exit(81)
transaction.stage=crash
p=build_proposal(sys.argv[1])
transaction.apply_proposal(p,expected_digest=p.digest)
"""
        crashed = self.python(script, self.repo)
        self.assertEqual(crashed.returncode, 81, crashed.stdout + crashed.stderr)
        self.assertEqual(inspect_recovery(self.repo)["status"], "recovery_required")
        result = recover_repository(self.repo)
        leftovers = list(self.repo.rglob(".autodev-init-*"))
        self.assertTrue(result.status == "recovery_required" or not leftovers,
                        f"recovery claimed {result.status} despite orphan staging: {leftovers}")
        self.assertFalse((self.repo / ".agent/PROJECT.yaml").exists())

    def test_process_death_after_parent_mkdir_cannot_claim_clean_orphan(self):
        script = """import os,sys
from autodev.init.proposal import build_proposal
from autodev.init.apply import apply_proposal
original=os.mkdir
def crash(path,*args,**kwargs):
 result=original(path,*args,**kwargs)
 if str(path).rstrip('/').split('/')[-1]=='contracts': os._exit(82)
 return result
os.mkdir=crash
p=build_proposal(sys.argv[1],project='contracts/PROJECT.yaml')
apply_proposal(p,expected_digest=p.digest)
"""
        crashed = self.python(script, self.repo)
        self.assertEqual(crashed.returncode, 82, crashed.stdout + crashed.stderr)
        self.assertEqual(inspect_recovery(self.repo)["status"], "recovery_required")
        result = recover_repository(self.repo)
        self.assertTrue(result.status == "recovery_required" or not (self.repo / "contracts").exists(),
                        f"recovery claimed {result.status} despite unrecorded created directory")

    def test_recovery_process_death_after_restore_is_idempotent(self):
        self.git("init", "-q")
        original = b"# exact original without final newline"
        (self.repo / ".gitignore").write_bytes(original)
        (self.repo / ".gitignore").chmod(0o640)
        crash_apply = """import os,sys
from autodev.init.proposal import build_proposal
from autodev.init.apply import apply_proposal
p=build_proposal(sys.argv[1],worktree_bucket='worktrees')
def stop(label,path):
 if label=='before_commit': os._exit(83)
apply_proposal(p,expected_digest=p.digest,checkpoint=stop)
"""
        crashed = self.python(crash_apply, self.repo)
        self.assertEqual(crashed.returncode, 83, crashed.stdout + crashed.stderr)
        crash_recovery = """import os,sys
from autodev.init.apply import recover_repository
def stop(label,path):
 if label=='after_restore' and path=='.gitignore': os._exit(84)
recover_repository(sys.argv[1],checkpoint=stop)
"""
        interrupted = self.python(crash_recovery, self.repo)
        self.assertEqual(interrupted.returncode, 84, interrupted.stdout + interrupted.stderr)
        recovered = recover_repository(self.repo)
        self.assertEqual(recovered.status, "recovered", recovered)
        self.assertEqual((self.repo / ".gitignore").read_bytes(), original)
        self.assertEqual((self.repo / ".gitignore").stat().st_mode & 0o777, 0o640)
        self.assertFalse((self.repo / ".agent/PROJECT.yaml").exists())
        self.assertEqual(inspect_recovery(self.repo)["status"], "clean")

    def test_parent_symlink_swap_during_staging_never_writes_outside_root(self):
        from autodev.safety.repository_files import stage
        parent = self.repo / "parent"
        (parent / "nested").mkdir(parents=True)
        outside = self.base / "outside"
        (outside / "nested").mkdir(parents=True)
        original_open = os.open
        swapped = []
        def swap_then_open(path, flags, *args, **kwargs):
            literal = str(path)
            if not swapped and (literal == "nested" or "/parent/nested/.autodev-init-" in literal):
                parent.rename(self.repo / "moved-parent")
                parent.symlink_to(outside, target_is_directory=True)
                swapped.append(True)
            return original_open(path, flags, *args, **kwargs)
        with patch("os.open", side_effect=swap_then_open):
            try:
                stage(self.repo, "parent/nested/target", b"reviewed bytes", 0o644)
            except (OSError, ValueError):
                pass
        self.assertTrue(swapped, "fault did not reach ancestor race boundary")
        self.assertEqual(list((outside / "nested").iterdir()), [], "staging escaped through changed ancestor")

    def test_two_processes_serialize_one_alignment_with_stable_lock(self):
        entered, release = self.base / "entered", self.base / "release"
        second_ready = self.base / "second-ready"
        script = """import json,sys,time
from pathlib import Path
from autodev.init.proposal import build_proposal
from autodev.init.apply import apply_proposal
p=build_proposal(sys.argv[1])
if sys.argv[2]=='second': Path(sys.argv[5]).write_text('proposal read during first intent')
def pause(label,path):
 if label=='after_intent' and sys.argv[2]=='first':
  Path(sys.argv[3]).write_text('locked')
  deadline=time.monotonic()+10
  while not Path(sys.argv[4]).exists() and time.monotonic()<deadline: time.sleep(.01)
print(json.dumps(apply_proposal(p,expected_digest=p.digest,checkpoint=pause).to_dict()))
"""
        first = subprocess.Popen([sys.executable, "-B", "-c", script, str(self.repo), "first", str(entered), str(release)], cwd=ROOT, env=ENV, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        self.addCleanup(lambda: first.poll() is None and first.kill())
        deadline = time.monotonic() + 10
        while not entered.exists() and first.poll() is None and time.monotonic() < deadline:
            time.sleep(.01)
        self.assertTrue(entered.exists(), "first process did not reach durable intent")
        second = subprocess.Popen([sys.executable, "-B", "-c", script, str(self.repo), "second", str(entered), str(release), str(second_ready)], cwd=ROOT, env=ENV, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        self.addCleanup(lambda: second.poll() is None and second.kill())
        deadline = time.monotonic() + 10
        while not second_ready.exists() and second.poll() is None and time.monotonic() < deadline:
            time.sleep(.01)
        self.assertTrue(second_ready.exists(), "second process did not inspect pending intent")
        release.write_text("continue")
        out1, err1 = first.communicate(timeout=20)
        out2, err2 = second.communicate(timeout=20)
        self.assertEqual((first.returncode, second.returncode), (0, 0), err1 + err2)
        statuses = [json.loads(out1)["status"], json.loads(out2)["status"]]
        self.assertEqual(statuses.count("applied"), 1, statuses)
        self.assertIn(statuses[1], {"stale_proposal", "recovery_required", "needs_input"})
        self.assertEqual(inspect_recovery(self.repo)["status"], "clean")
        self.assertEqual(len(list((self.repo / ".agent/.init-state").glob("locks/repository/*.lock"))), 1)


if __name__ == "__main__":
    unittest.main()
