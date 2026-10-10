# AutoDev v2 Agent Guide

AutoDev v2 is developed using bounded, retrieval-first context.

## Core rule

Context is fetched, not inherited.

Do not read the whole repository, all documentation, or the previous AutoDev repository before starting work.

Start from the selected milestone and retrieve additional information only when a concrete unanswered question requires it.

## Normal task context

For implementation work, read:

1. `AGENTS.md`
2. the selected `milestones/<ID>.md`
3. `context/SHARED-INVARIANTS.md`
4. the approved plan, if one exists
5. source and tests directly relevant to the task

Do not automatically read unrelated milestones, historical design documents, verification reports, or the old AutoDev repository.

## Planning

Use one `ralplan` for a milestone.

The plan must identify:

- objective
- scope
- exclusions
- affected components
- implementation slices
- acceptance criteria
- verification commands

Do not redesign requirements that are already explicit.

## Execution

Execute an approved plan with Ralph in bounded slices.

Prefer:

inspect → edit → run → observe → fix → verify

A new slice should reuse the approved milestone plan rather than starting another broad planning exercise.

## Context expansion

If required information is missing:

1. state the exact unresolved question;
2. identify the smallest authoritative source likely to answer it;
3. read only that source or section;
4. continue.

Broad documentation discovery is a fallback, not a starting step.

## Old AutoDev repository

The previous repository is historical/reference material.

Do not inspect it broadly.

Use `migration/OLD-REPO.md` first.

Open old files only when that migration map identifies them as relevant to the current task.

Old architecture and code are candidates for reuse, not automatic requirements.

## Engineering rules

- Work on one bounded objective at a time.
- Prefer the smallest correct implementation.
- Never invent approval or authority.
- Never weaken acceptance criteria.
- Preserve fail-closed behavior.
- Do not implement future milestones opportunistically.
- Tests and observable behavior outweigh agent self-report.
- Prefer executable verification over additional prose.

## Repository navigation

- `PRODUCT.md` — product direction and V0 boundary
- `context/` — small stable shared context
- `milestones/` — bounded work contracts
- `docs/plans/` — approved implementation plans
- `docs/verification/` — completion evidence
- `migration/` — maps to legacy material
- `src/` — implementation
- `tests/` — executable verification

Keep this file short. It is a router, not a specification.
