from __future__ import annotations

import unittest
from pathlib import Path

from tests.support import run_guarded_child


class FutureCommandTests(unittest.TestCase):
    def test_unknown_future_commands_exit_nonzero(self) -> None:
        result = run_guarded_child(Path(__file__).resolve().parents[1])
        for command in ("dispatch", "onboard", "supervise", "doctor", "run"):
            with self.subTest(command=command):
                self.assertEqual(result["unsupported_codes"][command], 2)
        self.assertFalse(result["unsupported_has_success"])


if __name__ == "__main__":
    unittest.main()
