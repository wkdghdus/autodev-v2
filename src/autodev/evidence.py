from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[2]
EVIDENCE_ROOT = REPO_ROOT / "evidence" / "AD-00"
FIXTURE_ROOT = REPO_ROOT / "fixtures" / "AD-00"
STATIC_INPUTS = frozenset(
    {
        "docs/plans/AD-00.md",
        "milestones/AD-00.md",
        "context/SHARED-INVARIANTS.md",
        "migration/SOURCES.md",
        "ROADMAP.yaml",
        "AGENTS.md",
        "migration/OLD-REPO.md",
        "migration/REFERENCE-MAP.md",
    }
)


class EvidenceError(ValueError):
    """Sanitized evidence-boundary error."""


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    assert_allowed_artifact(path)
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_json(path: Path) -> Any:
    assert_allowed_artifact(path)
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def source_records_path() -> Path:
    return EVIDENCE_ROOT / "source-records.json"


def input_manifest_path() -> Path:
    return EVIDENCE_ROOT / "input-manifest.json"


def fixture_manifest_path() -> Path:
    return EVIDENCE_ROOT / "fixture-manifest.json"


def load_source_records() -> dict[str, Any]:
    return load_json(source_records_path())


def load_input_manifest() -> dict[str, Any]:
    return load_json(input_manifest_path())


def load_fixture_manifest() -> dict[str, Any]:
    return load_json(fixture_manifest_path())


def assert_repo_relative(path_text: str) -> Path:
    if path_text.startswith("/") or ".." in Path(path_text).parts:
        raise EvidenceError("path must be repository-relative and non-escaping")
    raw_path = REPO_ROOT / path_text
    if _has_symlink_component(raw_path):
        raise EvidenceError("symlink inputs are not accepted for AD-00 evidence")
    path = raw_path.resolve()
    try:
        path.relative_to(REPO_ROOT)
    except ValueError as exc:
        raise EvidenceError("path escapes repository root") from exc
    return path


def manifest_input_paths() -> set[str]:
    manifest = load_input_manifest()
    return {entry["path"] for entry in manifest["entries"]}


def assert_manifest_input(path_text: str) -> Path:
    if path_text not in STATIC_INPUTS or path_text not in manifest_input_paths():
        raise EvidenceError("path is not in the AD-00 input manifest allowlist")
    return assert_repo_relative(path_text)


def assert_allowed_artifact(path: Path) -> Path:
    resolved = path.resolve()
    if _has_symlink_component(path.absolute()):
        raise EvidenceError("symlink inputs are not accepted for AD-00 evidence")
    allowed_roots = (EVIDENCE_ROOT, FIXTURE_ROOT)
    for root in allowed_roots:
        try:
            resolved.relative_to(root)
        except ValueError:
            continue
        return resolved
    try:
        rel = resolved.relative_to(REPO_ROOT).as_posix()
    except ValueError:
        raise EvidenceError("path is outside AD-00 evidence roots") from None
    if rel in STATIC_INPUTS:
        return resolved
    raise EvidenceError("path is not an AD-00 evidence artifact")


def read_allowed_provided_file(
    path: Path,
    *,
    expected_sha256: str,
    allowed_roots: tuple[Path, ...],
) -> bytes:
    resolved = path.resolve()
    if path.is_symlink() or any(
        _has_symlink_below(path.absolute(), root.absolute()) for root in allowed_roots
    ):
        raise EvidenceError("provided input must not be a symlink")
    if not any(_is_relative_to(resolved, root.resolve()) for root in allowed_roots):
        raise EvidenceError("provided input is outside the explicit allowlist")
    try:
        data = resolved.read_bytes()
    except OSError:
        raise EvidenceError("provided input could not be read") from None
    if sha256_bytes(data) != expected_sha256:
        raise EvidenceError("provided input hash mismatch")
    return data


def _is_relative_to(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
    except ValueError:
        return False
    return True


def _has_symlink_below(path: Path, root: Path) -> bool:
    if not _is_relative_to(path, root):
        return False
    current = root
    for part in path.relative_to(root).parts:
        current = current / part
        if current.is_symlink():
            return True
    return False


def _has_symlink_component(path: Path) -> bool:
    current = Path(path.anchor) if path.is_absolute() else Path()
    for part in path.parts:
        if part in ("", path.anchor):
            continue
        current = current / part
        try:
            if current.is_symlink():
                return True
        except OSError:
            return False
    return False
