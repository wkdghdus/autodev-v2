"""Deterministic rendering for new contracts only; existing bytes are never rendered."""
from __future__ import annotations

from collections.abc import Sequence


def _quote(value: str) -> str:
    if not isinstance(value, str) or any(ord(char) < 32 or ord(char) == 127 for char in value):
        raise ValueError("contract strings must contain printable text")
    return "'" + value.replace("'", "''") + "'"


def _paths(key: str, values: Sequence[str], indent: int = 2) -> list[str]:
    prefix = " " * indent
    if not values:
        return [f"{prefix}{key}: []"]
    return [f"{prefix}{key}:", *(f"{prefix}  - {_quote(item)}" for item in values)]


def render_project(project_id: str, name: str, slug: str, *, requirements: Sequence[str] = (),
                   context: Sequence[str] = (), acceptance: Sequence[str] = (),
                   execution_index: str = ".agent/EXECUTION.yaml") -> bytes:
    lines = ["schema_version: 2", "setup_state: draft", "project:",
             f"  id: {_quote(project_id)}", f"  slug: {_quote(slug)}", f"  name: {_quote(name)}", "sources:"]
    lines += _paths("requirements", requirements) + _paths("context", context)
    lines += ["  discovery:", "    roots: []", f"  execution_index: {_quote(execution_index)}",
              "execution:", "  harness: gajae", "  workflow: approved_roadmap_only",
              "  base_policy: dependencies_integrated", "  target_ref: null",
              "  max_active_milestones: 1", "  max_primary_actions_per_cycle: 1",
              "verification:", "  commands: []"]
    lines += _paths("acceptance_sources", acceptance)
    lines += ["  require_independent_review: true", "authority:", "  requested: {}"]
    return ("\n".join(lines) + "\n").encode("utf-8")


def render_execution(project_id: str) -> bytes:
    return (f"schema_version: 2\nproject_id: {_quote(project_id)}\nmilestones: []\n").encode("utf-8")
