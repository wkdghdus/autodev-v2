from __future__ import annotations

import json
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
BASELINE = ROOT / "docs" / "baseline" / "AD-00.md"
TEMPLATE = ROOT / "docs" / "baseline" / "environment-manifest.template.json"
DECISION = ROOT / "docs" / "decisions" / "AD-00-scope.md"


class BaselineTests(unittest.TestCase):
    def test_baseline_covers_required_unknown_families(self) -> None:
        text = BASELINE.read_text(encoding="utf-8")
        required = [
            "Sources and project identity",
            "Machine/runtime",
            "Hermes/GJC/native CLI compatibility",
            "Credentials/provider/billing",
            "Credentials/provider/billing/account route",
            "MCP discovered versus actual access",
            "Broker/session/worktree lifecycle",
            "Execution, journal, reconciliation, verification and revision applicability",
            "Scheduling, admission, delivery, restart and disable behavior",
            "Nous compatibility and current account state",
            "Historical F63 unavailable-service behavior",
            "UNKNOWN",
            "BLOCKED_EXTERNAL",
            "UNSUPPORTED",
            "Locator / provenance",
            "Later probe family",
            "Remediation / prerequisite",
        ]
        for item in required:
            self.assertIn(item, text)
        self.assertIn("must not become fabricated PASS results", text)

    def test_environment_template_is_non_secret_and_not_live_verified(self) -> None:
        template = json.loads(TEMPLATE.read_text(encoding="utf-8"))
        self.assertFalse(template["generated_values"])
        self.assertFalse(template["credentials"]["secret_values_included"])
        self.assertFalse(template["provenance"]["live_verified"])
        self.assertEqual(template["credentials"]["account_route"], "UNKNOWN")
        self.assertEqual(template["credentials"]["effective_auth_route"], "UNKNOWN")
        self.assertEqual(template["machine"]["project_identity"], "UNKNOWN")
        self.assertEqual(template["machine"]["repository_revision"], "UNKNOWN")
        self.assertEqual(template["machine"]["worktree_authority"], "UNKNOWN")
        self.assertEqual(template["machine"]["project_authority_artifacts"], "UNKNOWN")
        self.assertEqual(template["lifecycle"]["mcp_actual_access"], "UNKNOWN")
        self.assertEqual(template["lifecycle"]["journal_or_reconciliation_state"], "UNKNOWN")
        self.assertEqual(template["lifecycle"]["restart_disable_behavior"], "UNKNOWN")
        self.assertEqual(template["lifecycle"]["nous_compatibility"], "UNKNOWN")
        self.assertEqual(template["execution_traces"]["ready_real_trace"], "UNKNOWN")
        self.assertEqual(template["execution_traces"]["completed_real_trace"], "UNKNOWN")
        self.assertEqual(template["execution_traces"]["synthetic_fixture_source"], "fixtures/AD-00")
        serialized = json.dumps(template)
        self.assertNotRegex(serialized, r"(?i)(sk-|password-value|token-value|secret-value)")

    def test_scope_decision_records_exclusions(self) -> None:
        text = DECISION.read_text(encoding="utf-8")
        for excluded in ("credential", "cron", "provider", "AD-01", "dependency installation"):
            self.assertIn(excluded, text)


if __name__ == "__main__":
    unittest.main()
