# M1 — Repository Init

## Outcome

`autodev init <repo>` inspects a Git repository and produces a safe, reviewable alignment proposal without executing repository code or touching external infrastructure.

## Must support

- resolve the Git repository root;
- inventory existing project/context artifacts;
- recognize `AGENTS.md`, `CLAUDE.md`, `PROJECT.yaml`, and likely requirements/planning artifacts;
- report ambiguous candidates instead of guessing;
- produce deterministic dry-run output;
- make zero external/model/Hermes/Gajae effects;
- unchanged aligned repositories produce no proposed changes.

## Explicitly out of scope

- Hermes
- Gajae
- credentials
- cron
- execution
- approval
- autonomous coding
- external messaging

## Acceptance

1. Empty repository produces an honest incomplete proposal.
2. Existing `AGENTS.md` is preserved.
3. Ambiguous requirements sources are surfaced, not silently chosen.
4. No repository hooks or arbitrary repository code executes.
5. `--dry-run` changes nothing.
6. Repeated execution against unchanged input is deterministic.

## Planning guidance

Use one `ralplan` for this milestone.

The implementation plan should split execution into bounded Ralph slices rather than repeatedly re-planning the milestone.

Inspect `migration/OLD-REPO.md` before looking at legacy implementation. Reuse legacy code only when it directly reduces work required by this milestone.

Do not broadly inspect the previous repository or migrate unrelated AD-00–AD-23 architecture.
