# Previous AutoDev Repository

Source:
`wkdghdus/autodev`

Reference revision:
`b25242b302999f124cb5575ce7d49f3a20dc189d`

## Known implemented areas

### AD-00
Baseline scaffold, CLI boundaries, evidence/redaction foundations.

### AD-01
Contracts, models, validation, state/authority logic.

### AD-02
Storage, locks, subprocess safety, journals, passive Git inspection.

## Candidate implementation worth inspecting

- `autodev-v2/src/autodev/contracts/`
- `autodev-v2/src/autodev/safety/`
- `autodev-v2/src/autodev/redaction.py`
- `autodev-v2/src/autodev/effect_audit.py`
- `autodev-v2/tests/test_ad01_contracts.py`
- `autodev-v2/tests/test_ad02_safety.py`

## Historical material — do not load by default

- `AutoDev_v2_Complete_Specification.md`
- `00-PROJECT-SPECIFICATION.md`
- `01-EVIDENCE-AND-DECISIONS.md`
- `02-ACCEPTANCE-AND-FAULT-MATRIX.md`
- `04-CONTRACT-REFERENCE.md`
- `05-MILESTONE-PLAN.md`
- `milestones/AD-00.md` through `milestones/AD-23.md`

Use these only when a specific migration question cannot be answered from current requirements or implementation evidence.

## Known inconsistencies

The old README says no milestones were implemented, but AD-00, AD-01, and AD-02 implementation commits exist.

AD-02 has implementation/test evidence in its commit but no committed `docs/verification/AD-02.md`.

Do not make migration decisions based on the old README alone.
