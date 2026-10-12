# AD-00 scope decision

AD-00 uses an offline standard-library scaffold and metadata-only evidence
records to protect existing systems before future generalization.

Accepted scope:

- package import and module help smoke path;
- exact S1-S3 historical source metadata from `migration/SOURCES.md`;
- hashes for the small allowlist of AD-00 inputs consumed during execution;
- sanitized baseline and environment template with explicit unknowns;
- six synthetic state-label fixtures;
- test-local no-live-mutation harness with positive deny controls.

Excluded scope:

- live Nous, Hermes, GJC, cron, account, provider, billing, credential, MCP,
  gateway, or broker probes;
- future dispatch/onboarding/supervisor behavior;
- AD-01 state and authority schemas;
- dependency installation or external network access.

Missing source bodies and live compatibility evidence remain missing until
later milestones receive explicit authority and bounded probe criteria.
