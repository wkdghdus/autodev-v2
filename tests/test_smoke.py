from __future__ import annotations

import ast
import unittest
from pathlib import Path

from tests.support import run_guarded_child


ROOT = Path(__file__).resolve().parents[1]
PYTHON_FILES = [
    path
    for base in (ROOT / "src", ROOT / "tests")
    for path in base.rglob("*.py")
]


class SmokeTests(unittest.TestCase):
    def test_package_imports(self) -> None:
        result = run_guarded_child(ROOT)
        self.assertEqual(result["autodev_version"], "0.0.0")

    def test_module_help_exits_zero(self) -> None:
        result = run_guarded_child(ROOT)
        self.assertEqual(result["module_help_code"], 0)
        self.assertTrue(result["module_help_usage"])

    def test_python_sources_compile_in_memory(self) -> None:
        self.assertGreater(len(PYTHON_FILES), 0)
        for path in PYTHON_FILES:
            compile(path.read_text(encoding="utf-8"), str(path), "exec")

    def test_no_live_process_or_network_imports_in_package(self) -> None:
        blocked = {"subprocess", "socket", "urllib", "http"}
        for path in (ROOT / "src" / "autodev").rglob("*.py"):
            allow_subprocess = path.relative_to(ROOT / "src").as_posix() == "autodev/safety/runner.py"
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    names = {alias.name.split(".")[0] for alias in node.names}
                    if allow_subprocess:
                        names -= {"subprocess"}
                    self.assertFalse(names & blocked, f"{path} imports {names & blocked}")
                if isinstance(node, ast.ImportFrom) and node.module:
                    module_root = node.module.split(".")[0]
                    if allow_subprocess and module_root == "subprocess":
                        continue
                    self.assertNotIn(module_root, blocked, f"{path} imports {node.module}")

    def test_process_import_allowlist_rejects_dynamic_evasion(self) -> None:
        for path in (ROOT / "src" / "autodev").rglob("*.py"):
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
            for node in ast.walk(tree):
                if isinstance(node, ast.Name):
                    self.assertNotEqual(node.id, "__import__", str(path))
                if isinstance(node, ast.Import):
                    self.assertFalse(any(alias.name.split(".")[0] == "importlib" for alias in node.names), str(path))
                if isinstance(node, ast.ImportFrom) and node.module:
                    self.assertNotEqual(node.module.split(".")[0], "importlib", str(path))


if __name__ == "__main__":
    unittest.main()
