"""Pure, deterministic alignment proposals. No locks, stores, or writes occur here."""
from __future__ import annotations

import hashlib
import json
import re
import uuid
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from autodev.contracts import ContractError, load_execution_yaml, load_project_yaml, parse_yaml_subset
from autodev.contracts.validators import SLUG_RE, UUID_RE
from autodev.redaction import sanitize

from . import discovery as limits
from .discovery import Discovery, DiscoveryError, checked_path, safe_relative
from .render import render_execution, render_project

INIT_NAMESPACE = uuid.UUID("fdb5ac20-f552-5f54-8edf-556c94ec1e41")


def canonical_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"))


def _hash(data: bytes | None) -> str | None:
    return None if data is None else hashlib.sha256(data).hexdigest()


@dataclass(frozen=True)
class FileOperation:
    path: str
    original: bytes | None
    proposed: bytes
    mode: int = 0o644

    @property
    def after(self) -> bytes:
        return self.proposed

    @property
    def before_hash(self) -> str | None:
        return _hash(self.original)

    @property
    def after_hash(self) -> str:
        return hashlib.sha256(self.proposed).hexdigest()

    def to_dict(self) -> dict:
        result = {"path": self.path, "action": "create" if self.original is None else "append",
                "before_sha256": self.before_hash, "after_sha256": self.after_hash,
                "before_bytes": 0 if self.original is None else len(self.original),
                "after_bytes": len(self.proposed), "mode": self.mode}
        if self.original is None:
            result["proposed_text"] = self.proposed.decode("utf-8")
        elif self.proposed.startswith(self.original):
            result["appended_text"] = self.proposed[len(self.original):].decode("utf-8")
        displayed = sanitize(result)
        if displayed != result:
            displayed["display_redacted"] = True
        return displayed


@dataclass(frozen=True)
class Proposal:
    root: Path
    operations: tuple[FileOperation, ...]
    digest: str
    report: dict
    options: dict

    @property
    def status(self) -> str:
        return self.report["status"]

    def to_dict(self) -> dict:
        # Return a fresh JSON tree so consumers cannot mutate the stored report accidentally.
        report = json.loads(canonical_json({**self.report, "digest": self.digest}))
        displayed = sanitize(report)
        if displayed != report or any(operation.get("display_redacted") for operation in report["operations"]):
            displayed["display_redacted"] = True
        return displayed

    def to_json(self) -> str:
        return canonical_json(self.to_dict())


def _selection_map(selections: Any, discovery: Discovery) -> dict[str, tuple[str, ...]]:
    result: dict[str, list[str]] = {}
    values = [f"{key}={path}" for key, paths in selections.items() for path in ([paths] if isinstance(paths, str) else paths)] if isinstance(selections, dict) else list(selections)
    for value in values:
        if not isinstance(value, str) or "=" not in value:
            discovery.diagnostic("invalid_selection")
            continue
        category, path = value.split("=", 1)
        if category not in {"requirements", "context", "execution", "acceptance", "plans"}:
            discovery.diagnostic("invalid_selection_category")
            continue
        try:
            safe_relative(path)
        except DiscoveryError:
            discovery.diagnostic("unsafe_path", path)
            continue
        if path not in result.setdefault(category, []):
            result[category].append(path)
        discovery.read(path, required=True)
    return {key: tuple(sorted(paths)) for key, paths in sorted(result.items())}


def _error(discovery: Discovery, error: ContractError, path: str) -> None:
    for issue in error.issues:
        discovery.diagnostic(issue.code, path, field=issue.field)


def _existing(root: Path, path: str) -> bool:
    try:
        return checked_path(root, path).exists()
    except (DiscoveryError, OSError):
        return True


def build_proposal(repo: Path | str, *, selections: Any = (), project: str | None = None,
                   name: str | None = None, slug: str | None = None,
                   worktree_bucket: str | None = None) -> Proposal:
    """Read bounded repository evidence and return an exact, non-authoritative proposal."""
    supplied_root = Path(repo).absolute()
    root = supplied_root.resolve()
    discovery = Discovery(root, bucket=worktree_bucket)
    operations: list[FileOperation] = []
    unresolved: list[dict] = []
    selected: dict[str, tuple[str, ...]] = {}
    context_reads: list[dict] = []
    contract = None
    project_id = None
    project_path = project or ".agent/PROJECT.yaml"
    index_path = ".agent/EXECUTION.yaml"
    state: dict = {"ok": True, "state": "non_git", "common_dir": None}
    bucket_report: dict = {"ok": True, "reason": "worktree_strategy_unknown", "strategy": "unknown", "bucket": None}
    recovery = {"status": "clean", "diagnostics": [], "operations": []}

    try:
        # Resolve only after checking the original route: symlink components cannot authorize identity.
        for component in (supplied_root, *supplied_root.parents):
            if component.is_symlink():
                raise DiscoveryError("symlink_root", "")
        if not root.is_dir():
            raise DiscoveryError("repository_not_directory", "")
        safe_relative(project_path)
        if project_path.split("/")[0] == ".git" or project_path.startswith(".agent/.init-state/"):
            raise DiscoveryError("unsafe_contract_destination", project_path)
        checked_path(root, project_path, mutation=True)
    except (DiscoveryError, OSError) as error:
        discovery.diagnostic(error.code if isinstance(error, DiscoveryError) else "repository_unavailable", getattr(error, "path", ""))
        return _finish(root, operations, discovery, unresolved, selected, context_reads, state, bucket_report,
                       recovery, None, project_path, index_path, (), project, name, slug, worktree_bucket)

    conventional = [path for path in ("PROJECT.yaml", ".agent/PROJECT.yaml") if _existing(root, path)]
    if project is None:
        if len(conventional) > 1:
            discovery.diagnostic("multiple_projects")
            unresolved.append({"category": "project", "candidates": conventional,
                               "choices": [f"--project {path}" for path in conventional]})
        elif conventional:
            project_path = conventional[0]
    elif project_path not in conventional and any(path != project_path for path in conventional):
        discovery.diagnostic("project_identity_conflict", project_path)
        unresolved.append({"category": "project", "candidates": conventional,
                           "choices": [f"--project {path}" for path in conventional]})

    for conventional_path in conventional:
        discovery.read(conventional_path)

    original_project = discovery.read(project_path, mutation=True)
    if original_project is not None:
        try:
            contract = load_project_yaml(original_project)
            project_id = contract.project_id
            index_path = contract.sources["execution_index"]
            checked_path(root, index_path, mutation=True)
            if index_path.split("/")[0] == ".git" or index_path == ".agent/.init-state" or index_path.startswith(".agent/.init-state/"):
                raise DiscoveryError("unsafe_contract_destination", index_path)
            if name is not None or slug is not None:
                discovery.diagnostic("existing_project_metadata_immutable", project_path)
        except ContractError as error:
            _error(discovery, error, project_path)
        except DiscoveryError as error:
            discovery.diagnostic(error.code, error.path)

    extra_roots = tuple(contract.sources["discovery"]["roots"]) if contract else ()
    discovery.scan(extra_roots)
    if (root / ".agent").is_dir() and not (root / ".agent").is_symlink():
        discovery._scan_directory(".agent", 0)
    selection_map = _selection_map(selections, discovery)

    declared: dict[str, tuple[str, ...]] = {}
    if contract:
        declared = {"requirements": tuple(contract.sources["requirements"]),
                    "context": tuple(contract.sources["context"]), "acceptance": tuple(contract.acceptance_sources)}
        for category, paths in declared.items():
            for path in paths:
                data = discovery.read(path, required=True)
                if category == "context":
                    context_reads.append({"path": path, "status": "declared_context_read" if data is not None else "unreadable",
                                          "sha256": _hash(data), "bytes": len(data) if data is not None else 0,
                                          "runtime_ingestion": "unverified"})
            if paths and category in selection_map and set(selection_map[category]) != set(paths):
                discovery.diagnostic("existing_reference_immutable", project_path, field=category)

    for category in ("context", "requirements", "execution", "acceptance", "plans"):
        candidates = sorted(discovery.candidates[category])
        explicit = declared.get(category, ())
        # Existing contracts are immutable, including intentionally empty draft fields.
        if contract and category in declared:
            selected[category] = explicit
        elif explicit:
            selected[category] = explicit
        elif category in selection_map:
            chosen = selection_map[category]
            if category in {"execution", "plans"} and len(chosen) != 1:
                discovery.diagnostic("selection_requires_one", field=category)
            selected[category] = chosen
        elif len(candidates) == 1:
            selected[category] = tuple(candidates)
        elif len(candidates) > 1 and category != "plans":
            # An existing declared source can explicitly identify the roadmap too.
            referenced = sorted(set(candidates) & {path for paths in declared.values() for path in paths})
            if len(referenced) == 1:
                selected[category] = tuple(referenced)
            else:
                unresolved.append({"category": category, "candidates": candidates,
                                   "choices": [f"--select {category}={path}" for path in candidates]})
                discovery.diagnostic("ambiguous_candidates", field=category)
                selected[category] = ()
        else:
            selected[category] = ()
            if category in {"context", "requirements", "acceptance"} and not contract:
                discovery.diagnostic("missing_evidence", blocking=False, field=category)

    # Static metadata parsing is data validation only. No scripts, imports or toolchain commands.
    for path in discovery.candidates["metadata"]:
        data = discovery.contents.get(path)
        if data is None:
            continue
        try:
            if Path(path).name.casefold() in {"package.json", "package-lock.json"}:
                if not isinstance(json.loads(data), dict):
                    raise ValueError("metadata must be an object")
            elif Path(path).name.casefold() == "pyproject.toml":
                import tomllib
                tomllib.loads(data.decode("utf-8"))
        except (ValueError, UnicodeError):
            discovery.diagnostic("malformed_metadata", path, blocking=False)

    from autodev.safety.git_read import git_repository_state, managed_bucket_evidence
    state = asdict(git_repository_state(root))
    if not state["ok"]:
        discovery.diagnostic(state["reason"])
    elif state["state"] in {"non_git", "unborn", "detached"}:
        discovery.diagnostic("git_" + state["state"], blocking=False)
    bucket = managed_bucket_evidence(root, worktree_bucket,
                                    excluded_paths=tuple(sorted({*limits.ROOTS, *extra_roots, project_path, index_path})),
                                    read_bytes=lambda path: discovery.read(path, inspect_parents=False))
    bucket_report = asdict(bucket)
    ignore_original = bucket_report.pop("ignore_original", None)
    ignore_proposed = bucket_report.pop("ignore_proposed", None)
    if not bucket.ok:
        discovery.diagnostic(bucket.reason, worktree_bucket or "")
    elif ignore_proposed is not None:
        # Read through the shared budget and mutation-target safety path too.
        observed_ignore = discovery.read(".gitignore", mutation=True)
        if observed_ignore != ignore_original:
            discovery.diagnostic("ignore_evidence_changed", ".gitignore")
        else:
            mode = discovery.inventory[".gitignore"]["mode"] if observed_ignore is not None else 0o644
            operations.append(FileOperation(".gitignore", ignore_original, ignore_proposed, mode))

    original_index = discovery.read(index_path, mutation=True)
    if project_id is None and original_project is None and original_index is not None:
        try:
            raw = parse_yaml_subset(original_index, source_name=index_path)
            peer_id = raw.get("project_id") if isinstance(raw, dict) else None
            if not isinstance(peer_id, str) or not UUID_RE.fullmatch(peer_id):
                discovery.diagnostic("invalid_uuid", index_path, field="project_id")
            else:
                project_id = peer_id
        except ContractError as error:
            _error(discovery, error, index_path)

    if project_id is None:
        project_id = str(uuid.uuid5(INIT_NAMESPACE, canonical_json([str(root), state.get("common_dir") or "non-git"])))
    new_project = original_project
    if original_project is None:
        label = name if name is not None else root.name
        display_slug = slug if slug is not None else re.sub(r"[^a-z0-9]+", "-", label.casefold()).strip("-")
        if not label or any(ord(char) < 32 or ord(char) == 127 for char in label):
            discovery.diagnostic("invalid_project_name", project_path, field="--name")
        if not SLUG_RE.fullmatch(display_slug):
            discovery.diagnostic("invalid_project_slug", project_path, field="--slug")
        if label and SLUG_RE.fullmatch(display_slug) and not any(ord(char) < 32 or ord(char) == 127 for char in label):
            try:
                new_project = render_project(project_id, label, display_slug,
                                             requirements=selected.get("requirements", ()), context=selected.get("context", ()),
                                             acceptance=selected.get("acceptance", ()), execution_index=index_path)
                contract = load_project_yaml(new_project)
                operations.append(FileOperation(project_path, None, new_project))
            except (ValueError, ContractError) as error:
                if isinstance(error, ContractError):
                    _error(discovery, error, project_path)
                else:
                    discovery.diagnostic("unsupported_rendered_text", project_path)
    if contract:
        new_index = original_index if original_index is not None else render_execution(contract.project_id)
        try:
            load_execution_yaml(new_index, contract)
            if original_index is None:
                operations.append(FileOperation(index_path, None, new_index))
        except ContractError as error:
            _error(discovery, error, index_path)
    if project_path == index_path:
        discovery.diagnostic("contract_destination_collision", project_path)

    # Lazy import avoids apply/proposal cycles and keeps recovery inspection read-only.
    from .apply import inspect_recovery
    recovery = inspect_recovery(root)
    if recovery["status"] != "clean":
        discovery.diagnostic(recovery["status"], ".agent/.init-state")

    return _finish(root, operations, discovery, unresolved, selected, context_reads, state, bucket_report,
                   recovery, contract, project_path, index_path, selection_map, project, name, slug, worktree_bucket)


def _finish(root: Path, operations: list[FileOperation], discovery: Discovery, unresolved: list[dict],
            selected: dict, context_reads: list[dict], state: dict, bucket_report: dict,
            recovery: dict, contract: Any, project_path: str, index_path: str, selection_map: Any,
            project: str | None, name: str | None, slug: str | None, worktree_bucket: str | None) -> Proposal:
    diagnostics = sorted(discovery.diagnostics, key=lambda item: (item["code"], item.get("field", ""), item["path"]))
    blocked = any(item["blocking"] for item in diagnostics)
    # No partially applicable operations are exposed when any safety/choice requirement is unresolved.
    applicable_operations = () if blocked else tuple(sorted(operations, key=lambda operation: operation.path))
    canonical_selections = tuple(f"{category}={path}" for category, paths in sorted(dict(selection_map).items()) for path in paths)
    options = {"selections": canonical_selections, "project": project, "name": name, "slug": slug,
               "worktree_bucket": worktree_bucket}
    status = "recovery_required" if recovery["status"] == "recovery_required" else "needs_input" if blocked else "preview" if applicable_operations else "noop"
    report = {"schema_version": 1, "operation": "init", "status": status,
              "setup_state": contract.setup_state if contract else "draft", "lifecycle_ready": False,
              "identity": {"repository": str(root), "git_common_dir": state.get("common_dir"),
                           "project_id": contract.project_id if contract else None},
              "project_path": project_path, "execution_index_path": index_path,
              "diagnostics": diagnostics, "candidates": {key: sorted(value) for key, value in discovery.candidates.items()},
              "unresolved": unresolved, "selected": {key: list(value) for key, value in sorted(selected.items())},
              "declared_context": sorted(context_reads, key=lambda item: item["path"]),
              "runtime_ingestion": "unverified", "git": state, "worktree": bucket_report,
              "recovery": recovery, "operations": [operation.to_dict() for operation in applicable_operations],
              "effects": {"alignment_writes": len(applicable_operations), "preview_writes": 0,
                          "apply_private_state": [".agent/.init-state/owner.json", ".agent/.init-state/<repository-lock>",
                                                  ".agent/.init-state/<transaction-record>"],
                          "apply_temporary_files": "same-directory owned staging files for reviewed operations",
                          "execution_enabled": False},
              "discovery": {"registry_version": limits.REGISTRY_VERSION, "entries": discovery.entries,
                            "content_bytes": discovery.bytes_read, "inventory": discovery.result_inventory(),
                            "recognition_scope": ["PROJECT.yaml", ".agent/PROJECT.yaml", "explicit --project"],
                            "limits": {"depth": limits.MAX_DEPTH, "entries": limits.MAX_ENTRIES,
                                       "candidates": limits.MAX_CANDIDATES, "file_bytes": limits.MAX_FILE_BYTES,
                                       "content_bytes": limits.MAX_TOTAL_BYTES}},
              "binding_scope": "canonical repository and Git identity, explicit selections, bounded inventory names and candidate/reference contents, target bytes, Git index/config/status and ignore evidence"}
    binding = {"report": report, "options": options,
               "reads": {path: _hash(data) for path, data in sorted(discovery.contents.items())},
               "operations": [operation.to_dict() for operation in applicable_operations]}
    digest = hashlib.sha256(canonical_json(binding).encode("utf-8")).hexdigest()
    return Proposal(root, applicable_operations, digest, report, options)
