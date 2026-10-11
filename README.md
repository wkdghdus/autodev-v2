# AutoDev v2

AutoDev is a safe, reusable alignment and supervision layer for autonomous
software-development workflows built around existing project authority.

## Development model

AutoDev follows a predefined AD-00 through AD-23 milestone roadmap.

Start with:

- `PRODUCT.md` — product direction
- `ROADMAP.yaml` — milestone sequence, dependencies, and state
- `AGENTS.md` — agent context/execution policy
- `milestones/` — individual milestone contracts
- `context/SHARED-INVARIANTS.md` — cross-milestone rules

Historical AutoDev material is not default development context.

Use:

- `migration/OLD-REPO.md`
- `migration/SOURCES.md`
- `migration/REFERENCE-MAP.md`

for targeted legacy retrieval.

## Current milestone

**AD-00 — Baseline, scope lock, and evidence inventory**

This repository intentionally begins again from AD-00.

The previous AutoDev repository contains partial implementation of AD-00 through
AD-02. That code may be selectively inspected and reused, but every milestone in
this repository must be verified against the current contract.

## Milestone loop

Each milestone follows:

1. select the current `ready` milestone from `ROADMAP.yaml`;
2. load only its bounded context;
3. run one `ralplan`;
4. save the implementation plan under `docs/plans/`;
5. execute bounded Ralph slices;
6. independently verify the acceptance criteria;
7. save evidence under `docs/verification/`;
8. mark the milestone complete;
9. advance the next intended milestone.

The full historical specification and roadmap are never required as default
planning context.
