# AutoDev v2 Agent Guide

AutoDev v2 uses bounded, retrieval-first context.

## Core rule

**Context is fetched, not inherited.**

Do not begin a task by reading the entire repository, all milestones,
historical specifications, or the previous AutoDev repository.

Start from the current milestone and retrieve additional context only
to answer a concrete unresolved question.

## Milestone routing

`ROADMAP.yaml` is the authoritative milestone index.

It tells you:

- which milestones exist;
- their intended sequence;
- dependencies;
- file locations;
- current execution status.

`ROADMAP.yaml` is navigation metadata, not implementation requirements.

The selected `milestones/<ID>.md` file is the implementation contract
for that milestone.

Do not open unrelated milestone files merely because they exist.

## Default planning context

For a milestone planning session, begin with only:

1. `AGENTS.md`
2. `ROADMAP.yaml`
3. the selected `milestones/<ID>.md`
4. `context/SHARED-INVARIANTS.md`

Then inspect directly relevant current source/tests.

Read `PRODUCT.md` only when the milestone leaves a product-boundary
question unresolved.

Read predecessor verification only when the current milestone needs
evidence about what the predecessor actually delivered.

## Legacy references

The previous AutoDev repository is reference material, not inherited
architecture.

Use these routers first:

- `migration/OLD-REPO.md`
- `migration/SOURCES.md`
- `migration/REFERENCE-MAP.md`

If the current milestone mentions an `Fxx` fault, `Gxx` gate, historical
contract, or incident, use the reference map to locate that exact source.

Do not broadly read the old specification or old roadmap.

## Context expansion

When information is missing:

1. state the exact unresolved question;
2. identify the smallest authoritative source likely to answer it;
3. read only the relevant source or section;
4. continue.

Do not expand context merely to "understand everything."

## Planning

Use one implementation plan for one milestone.

The plan must identify:

- objective;
- scope;
- exclusions;
- affected components;
- relevant existing implementation;
- acceptance criteria;
- verification commands;
- bounded implementation slices.

Do not redesign explicit requirements.

Do not start a new broad planning cycle for every implementation slice.

## Execution

Execute the approved plan in bounded implementation slices.

Prefer:

inspect -> edit -> run -> observe -> fix -> verify

Each slice should use:

- the selected milestone;
- its approved plan;
- the current slice;
- directly relevant source/tests;
- targeted additional context only when required.

Do not implement future milestones opportunistically.

## Verification

Executor self-report is not completion evidence.

Completion requires reproducible evidence against the milestone's
acceptance criteria.

After implementation, write:

`docs/verification/<ID>.md`

Include:

- changed files;
- commands and exit codes;
- criterion-by-criterion evidence;
- relevant effect/safety audit;
- known limitations;
- blocked live validation where applicable.

A milestone must not be marked complete before verification exists.

## Roadmap advancement

Only one milestone should normally be active.

Statuses in `ROADMAP.yaml` are explicit state, not automatically inferred
from dependencies.

After a milestone is independently verified:

1. mark it `complete`;
2. mark the next intended milestone `ready`;
3. keep later milestones `blocked`.

If multiple milestones are technically dependency-ready, follow roadmap
sequence unless the operator explicitly selects another one.

## Engineering rules

- Prefer the smallest correct implementation.
- Never invent product direction.
- Never invent authority or approval.
- Never weaken acceptance criteria.
- Preserve fail-closed behavior.
- Missing evidence remains missing.
- Simulated evidence is never live evidence.
- Current execution state belongs in deterministic records.
- Tests and observed behavior outrank agent narration.

## Repository map

- `PRODUCT.md` — product direction
- `ROADMAP.yaml` — milestone navigation and state
- `milestones/` — bounded milestone contracts
- `context/` — stable shared context
- `docs/plans/` — approved implementation plans
- `docs/verification/` — completion evidence
- `migration/` — legacy lookup/reference maps
- `src/` — implementation
- `tests/` — executable verification

This file is a signpost, not a project encyclopedia.
