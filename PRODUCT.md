# AutoDev v2

## Problem

Setting up an autonomous development workflow for a new software project currently requires too much manual configuration and repeated troubleshooting across project context, Hermes, Gajae, execution state, validation, and scheduling.

AutoDev exists to make that setup reproducible and safe.

## Product direction

AutoDev should take an existing Git repository and progressively align it for supervised autonomous development.

The human decides what should be built.

AutoDev helps establish the environment in which approved work can be planned, executed, verified, recovered, and eventually supervised automatically.

## V0 goal

The first useful capability is:

> `autodev init <repo>`

Given a Git repository, AutoDev should inspect its existing project artifacts and propose the minimum repository-local configuration needed to make the project's development intent machine-readable.

V0 should help identify things such as:

- project context/instructions;
- requirements or product authority;
- milestones or plans;
- acceptance criteria;
- relevant toolchain information;
- missing required project metadata.

It should preserve existing files wherever possible.

## V0 output

`autodev init` should produce a reviewable proposal before changing anything.

When information is ambiguous or missing, it should say so rather than guessing.

Repeated execution against an unchanged aligned repository should be a no-op.

## V0 non-goals

V0 does not:

- configure Hermes;
- configure Gajae;
- create coding sessions;
- call an LLM;
- inspect credentials;
- configure providers;
- create cron jobs;
- send messages;
- execute project hooks;
- approve milestones;
- begin autonomous coding;
- mutate external infrastructure.

Those capabilities may come later.

## Product principles

### Thin harness

Prefer strong agents operating inside small deterministic boundaries over large orchestration systems.

### Progressive disclosure

Agents begin with minimal context and retrieve deeper information only when necessary.

### Existing project first

AutoDev adapts to the project rather than forcing every repository into one predefined documentation layout.

### Fail closed

Unknown authority, ambiguous state, unsupported behavior, or missing evidence must not silently become permission.

### Human product authority

AutoDev may organize and execute approved work.

It does not invent product direction.

### Evidence over narration

Tests, observable system state, hashes, receipts, and reproducible commands are stronger evidence than an agent claiming that work is complete.
