from __future__ import annotations

import json
import unittest
from pathlib import Path

from tests.support import run_guarded_child


class EffectAuditTests(unittest.TestCase):
    def test_real_app_paths_run_in_preimport_guarded_child(self) -> None:
        result = run_guarded_child(Path(__file__).resolve().parents[1])
        self.assertEqual(result["autodev_version"], "0.0.0")
        self.assertEqual(result["help_code"], 0)
        self.assertTrue(result["help_usage"])
        self.assertEqual(result["module_help_code"], 0)
        self.assertTrue(result["module_help_usage"])
        self.assertEqual(result["unsupported_code"], 2)
        self.assertTrue(result["protected_unchanged"])
        self.assertTrue(result["canary_absent"])
        self.assertEqual(result["tamper_message"], "provided input hash mismatch")
        self.assertEqual(result["source_count"], 3)
        self.assertEqual(result["fixture_count"], 6)
        self.assertGreaterEqual(result["input_count"], 8)
        self.assertEqual(
            set(result["controls"]),
            {"lowlevel-write", "network", "network-connect", "process", "process-system", "read", "write"},
        )
        self.assertEqual(
            set(result["attempt_kinds"]),
            {"network-denied", "process-denied", "read-denied", "write-allowed", "write-denied"},
        )
        self.assertEqual(result["parent_child_launch"], "fixed-python-guarded-script")

    def test_positive_controls_deny_protected_write_process_and_network(self) -> None:
        result = run_guarded_child(Path(__file__).resolve().parents[1])
        self.assertTrue(result["protected_unchanged"])
        kinds = {attempt["kind"] for attempt in result["attempts"]}
        self.assertTrue({"write-denied", "process-denied", "network-denied"} <= kinds)

    def test_audit_output_does_not_include_canary(self) -> None:
        result = run_guarded_child(Path(__file__).resolve().parents[1])
        self.assertTrue(result["canary_absent"])
        self.assertNotIn("CHILD-CANARY-secret-value", json.dumps(result))


if __name__ == "__main__":
    unittest.main()
