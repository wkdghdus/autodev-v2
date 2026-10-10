# Shared Invariants

These rules apply across AutoDev unless a later explicitly approved product decision changes them.

## Safety

- Unknown authority does not imply permission.
- Generated configuration cannot approve itself.
- Ambiguity fails closed.
- AutoDev must not weaken acceptance criteria to obtain a passing result.
- Destructive or externally visible effects require explicit authority.

## Context

- Load only context relevant to the current objective.
- Historical documents are not default context.
- Retrieve additional information only to answer a concrete unresolved question.
- Prefer authoritative source material over summaries when resolving a contradiction.

## Scope

- A milestone may implement only its approved scope.
- Future capability may be represented by a failing/unsupported boundary where necessary, but must not be silently implemented.
- Small plan-consistent fixes are preferred over unrelated refactoring.

## Verification

- Executor self-report is not completion evidence.
- Acceptance criteria must be independently checkable.
- Mocked evidence must not be represented as live evidence.
- Missing evidence remains missing.

## State

- Current project/runtime state belongs in deterministic records, not conversational memory.
- Durable identity must not depend only on display names or slugs.
- Uncertain execution must be reconciled before duplicate mutation is attempted.

## Migration

- Previous AutoDev behavior is not automatically normative.
- Old code may be reused after inspection.
- Old specifications may explain intent but should not be copied wholesale into current context.
- Every migrated behavior must be justified by the current product boundary or current milestone.
