from __future__ import annotations

import json
import unittest

from autodev.evidence import assert_repo_relative, load_fixture_manifest, sha256_file


class FixtureTests(unittest.TestCase):
    def test_fixture_manifest_covers_all_synthetic_states(self) -> None:
        manifest = load_fixture_manifest()
        fixtures = manifest["fixtures"]
        self.assertEqual(
            {fixture["id"] for fixture in fixtures},
            {"ready", "active", "uncertain", "verifying", "human-blocked", "completed"},
        )
        for fixture in fixtures:
            path = assert_repo_relative(fixture["path"])
            self.assertEqual(sha256_file(path), fixture["measured_sha256"], fixture["id"])
            self.assertEqual(fixture["provenance"], "generated AD-00 synthetic example fixture")
            data = json.loads(path.read_text(encoding="utf-8"))
            self.assertTrue(data["synthetic"])
            self.assertFalse(data["live_trace"])
            self.assertEqual(data["status_claim"], "synthetic example only")
            self.assertEqual(data["fixture_id"], fixture["id"])


if __name__ == "__main__":
    unittest.main()
