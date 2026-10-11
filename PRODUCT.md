# AutoDev v2

## Problem

Setting up an autonomous development workflow for a new software project
currently requires too much manual configuration and repeated troubleshooting
across project context, Hermes, Gajae, execution state, validation, recovery,
and scheduling.

AutoDev exists to make that setup reproducible and safe.

## Product direction

AutoDev takes an existing Git repository and progressively aligns it for
supervised autonomous development.

The human decides what should be built.

AutoDev establishes the environment in which approved work can be:

- represented deterministically;
- planned;
- executed;
- verified;
- recovered safely;
- and eventually supervised automatically.

AutoDev is not the product owner.

It operates on already-approved project direction.

## Initial user-facing target

The first major user-facing workflow is:

> `autodev init <repo>`

Given a Git repository, AutoDev should inspect existing project artifacts and
propose the minimum repository-local alignment needed to make development
intent machine-readable.

It should identify or surface:

- project context and agent instructions;
- requirements or product authority;
- milestones and plans;
- acceptance criteria;
- execution metadata;
- relevant toolchain information;
- missing required project metadata.

It should preserve existing files and explicit user choices wherever possible.

## Implementation sequence

`autodev init` is a user-facing target, not the first implementation milestone.

AutoDev first establishes foundational contracts and safety primitives.

The implementation roadmap begins:

1. **AD-00** — Baseline, scope lock, and evidence inventory
2. **AD-01** — Schemas, identities, authority, and orthogonal states
3. **AD-02** — Safe storage, command execution, locks, and journals
4. **AD-03** — Friendly init and conservative artifact discovery

Later milestones progressively introduce:

- execution-index and approval binding;
- runtime compatibility;
- credential and billing-route auditing;
- resource admission;
- Hermes/Gajae integration;
- lifecycle reconciliation;
- guarded execution;
- supervision;
- independent verification;
- onboarding;
- gateway and scheduling;
- disable/recovery;
- adversarial validation;
- Nous migration;
- second-project validation;
- release.

`ROADMAP.yaml` defines the implementation sequence and current status.

## Init behavior

`autodev init` should produce a reviewable proposal before making changes.

When information is ambiguous or missing, it should surface uncertainty rather
than guess.

Repeated execution against an unchanged aligned repository should converge to
a no-op.

## Product principles

### Thin harness

Prefer strong agents operating inside small deterministic boundaries over a
large custom orchestration framework.

### Progressive disclosure

Agents begin with the smallest useful context and retrieve deeper information
only when necessary.

### Existing project first

AutoDev adapts to a project's existing structure rather than forcing every
repository into one documentation layout.

### Fail closed

Unknown authority, ambiguous state, unsupported behavior, or missing evidence
must not silently become permission.

### Human product authority

AutoDev may organize and execute approved work.

It does not invent product direction or approve itself.

### Deterministic state

Important project, approval, execution, and recovery state belongs in durable
records rather than conversational memory.

### Evidence over narration

Tests, observable state, hashes, receipts, native identifiers, and reproducible
commands are stronger evidence than an agent claiming work is complete.

### Safe reuse

Legacy AutoDev implementation may be reused when it satisfies the current
milestone.

Historical code is candidate implementation, not automatic architecture.
