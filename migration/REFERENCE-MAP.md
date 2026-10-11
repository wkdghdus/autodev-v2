# Legacy Reference Map

This file routes milestone-specific historical references without requiring an
agent to load the complete old AutoDev documentation set.

Legacy repository:

`wkdghdus/autodev`

Pinned revision:

`b25242b302999f124cb5575ce7d49f3a20dc189d`

## Fault IDs: F01-F70

When a milestone references an `Fxx` identifier, retrieve the specific row from:

`autodev-v2/02-ACCEPTANCE-AND-FAULT-MATRIX.md`

Do not load the full matrix unless the selected milestone requires a broad audit
such as AD-20.

## Contract definitions

When a milestone requires the detailed historical definition of:

- `PROJECT.yaml`
- `EXECUTION.yaml`
- installation records
- operation journals
- validation receipts
- mutation grants
- repair/validation/recovery plans
- compatibility manifests
- resource admission records
- retention/locking semantics

retrieve only the relevant section from:

`autodev-v2/04-CONTRACT-REFERENCE.md`

These are historical implementation targets and must still be evaluated against
the current milestone and shared invariants.

## Gate IDs: G00-G13

When AD-15 or a later milestone references `G00` through `G13`, retrieve the gate
sequence from:

`autodev-v2/00-PROJECT-SPECIFICATION.md`

Relevant section:

`12.2 Gate sequence`

The historical gate sequence defines:

- G00 repo/contract/index identity
- G01 runtime compatibility
- G02 provider/auth/billing/resource coverage
- G03 minimal inference
- G04 direct planning workflow
- G05 MCP configuration/discovery
- G06 real read-only Coordinator tool invocation
- G07 managed lifecycle creation
- G08 Hermes-to-GJC planning workflow
- G09 bounded diagnostic execution
- G10 independent second-wake reconciliation
- G11 terminal verification
- G12 gateway/scheduled-worker environment and delivery
- G13 admission/disable/restart/uncertainty negative tests

Read the original section before implementing or verifying these gates.

## Historical decisions and incident traceability

If a requirement's reason or source conflict cannot be resolved from the current
milestone, retrieve the relevant section from:

`autodev-v2/01-EVIDENCE-AND-DECISIONS.md`

Use it to understand historical rationale, not as blanket permission to broaden
the milestone.

## Historical source metadata

For S1-S3 identities and external references, use:

`autodev-v2/reference/SOURCES.md`

and the local:

`migration/SOURCES.md`

## Legacy implementation

For candidate reusable code, consult:

`migration/OLD-REPO.md`

before opening old implementation files.

## Files not loaded by default

Do not load these merely for general understanding:

- `AutoDev_v2_Complete_Specification.md`
- `autodev-v2/00-PROJECT-SPECIFICATION.md`
- `autodev-v2/01-EVIDENCE-AND-DECISIONS.md`
- `autodev-v2/02-ACCEPTANCE-AND-FAULT-MATRIX.md`
- `autodev-v2/04-CONTRACT-REFERENCE.md`
- `autodev-v2/05-MILESTONE-PLAN.md`

Retrieve only the relevant section when a concrete question requires it.
