from __future__ import annotations

import tempfile
import traceback
import unittest
from pathlib import Path

from autodev.evidence import (
    EvidenceError,
    REPO_ROOT,
    assert_manifest_input,
    assert_repo_relative,
    load_input_manifest,
    read_allowed_provided_file,
    load_source_records,
    sha256_bytes,
    sha256_file,
    assert_allowed_artifact,
)


class SourceRecordTests(unittest.TestCase):
    def test_parent_symlink_is_rejected_before_read(self) -> None:
        with tempfile.TemporaryDirectory(dir=REPO_ROOT) as tmp:
            root = Path(tmp)
            actual = root / "actual"
            actual.mkdir()
            provided = actual / "provided.txt"
            provided.write_bytes(b"provided")
            link = root / "link"
            link.symlink_to(actual, target_is_directory=True)
            with self.assertRaises(EvidenceError):
                read_allowed_provided_file(
                    link / "provided.txt",
                    expected_sha256=sha256_bytes(b"provided"),
                    allowed_roots=(root,),
                )
            link.unlink()
            link.symlink_to(REPO_ROOT / "evidence" / "AD-00", target_is_directory=True)
            with self.assertRaises(EvidenceError):
                assert_allowed_artifact(link / "source-records.json")

    def test_s1_s2_s3_exact_metadata_and_unavailable_bodies(self) -> None:
        records = load_source_records()
        self.assertEqual(records["legacy_repository"], "wkdghdus/autodev")
        self.assertEqual(records["legacy_revision"], "b25242b302999f124cb5575ce7d49f3a20dc189d")
        by_id = {record["id"]: record for record in records["records"]}
        self.assertEqual(set(by_id), {"S1", "S2", "S3"})
        expected = {
            "S1": (
                "Lessons Learned from Nous Autonomous Supervisor Setup.",
                "Pasted markdown(2).md",
                "6ace331bbf3f2ee7af23b46f8cbd579290c434e0f3d913a0e0eccc2d035b928d",
            ),
            "S2": (
                "Hermes + Gajae Automated Onboarding: Lessons from Nous.",
                "Pasted markdown (2).md",
                "d0ea218d74b658f174bd8566c8bf017981b06d7df51a12df4ecb94e997bf052b",
            ),
            "S3": (
                "Lessons Learned From Nous Autonomous Onboarding.",
                "Pasted markdown (3).md",
                "bdac1bb84c3de3f695462d371ee3509e9a98007f9091b2292ad6f83eb2dd43b5",
            ),
        }
        for source_id, values in expected.items():
            record = by_id[source_id]
            self.assertEqual((record["title"], record["recorded_filename"], record["recorded_sha256"]), values)
            self.assertEqual(record["evidence_class"], "PROVIDED_FILE")
            self.assertEqual(record["body_status"], "UNAVAILABLE")
            self.assertIsNone(record["measured_sha256"])
            self.assertFalse(record["live_verified"])
            self.assertEqual(record["observations"], [])
            self.assertEqual(record["proposed_requirements"], [])
            self.assertIsNone(record["unavailable_extraction"])

    def test_available_input_hashes_recompute(self) -> None:
        manifest = load_input_manifest()
        self.assertGreaterEqual(len(manifest["entries"]), 8)
        for entry in manifest["entries"]:
            path = assert_repo_relative(entry["path"])
            self.assertTrue(path.is_file(), entry["path"])
            self.assertEqual(sha256_file(path), entry["measured_sha256"], entry["path"])
            self.assertEqual(assert_manifest_input(entry["path"]), path)
            self.assertIn("provenance", entry)
            self.assertIn("observations", entry)
            self.assertIn("proposed_requirements", entry)
            self.assertFalse(entry["live_verified"])

    def test_manifest_allowlist_rejects_unlisted_paths(self) -> None:
        with self.assertRaises(ValueError):
            assert_manifest_input("README.md")

    def test_provided_file_reader_rejects_tamper_and_sanitizes_errors(self) -> None:
        secret_path_fragment = "secret-token-value"
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            provided = root / f"{secret_path_fragment}.txt"
            provided.write_text("provided\n", encoding="utf-8")
            expected = sha256_bytes(provided.read_bytes())
            self.assertEqual(
                read_allowed_provided_file(
                    provided,
                    expected_sha256=expected,
                    allowed_roots=(root,),
                ),
                b"provided\n",
            )
            with self.assertRaises(EvidenceError) as mismatch:
                read_allowed_provided_file(
                    provided,
                    expected_sha256=sha256_bytes(b"changed\n"),
                    allowed_roots=(root,),
                )
            self.assertEqual(str(mismatch.exception), "provided input hash mismatch")

            outside = REPO_ROOT / "README.md"
            with self.assertRaises(EvidenceError) as outside_error:
                read_allowed_provided_file(
                    outside,
                    expected_sha256=sha256_bytes(b""),
                    allowed_roots=(root,),
                )
            self.assertNotIn(str(outside), str(outside_error.exception))
            self.assertNotIn(secret_path_fragment, str(outside_error.exception))
            self.assertNotIn(secret_path_fragment, "".join(traceback.format_exception(outside_error.exception)))

    def test_changed_byte_negative_control(self) -> None:
        original = b"stable input\n"
        changed = b"stable input!\n"
        self.assertNotEqual(sha256_bytes(original), sha256_bytes(changed))

    def test_path_boundary_rejects_absolute_traversal_and_symlink(self) -> None:
        with self.assertRaises(ValueError):
            assert_repo_relative("/tmp/outside")
        with self.assertRaises(ValueError):
            assert_repo_relative("../outside")
        with tempfile.TemporaryDirectory(dir=REPO_ROOT) as tmp:
            link = Path(tmp) / "escape"
            link.symlink_to(REPO_ROOT / "milestones" / "AD-00.md")
            rel = link.relative_to(REPO_ROOT).as_posix()
            with self.assertRaises(ValueError):
                assert_repo_relative(rel)


if __name__ == "__main__":
    unittest.main()
