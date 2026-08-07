# ADR-004: Redaction scope and correlation

- **Status:** Accepted for Framework v1
- **Context:** Redaction can preserve or destroy equality used for diagnostic correlation. Independent workload token algorithms can create accidental cross-artifact or cross-session joins.
- **Decision:** Redaction is a shared architectural contract, not a workload-local convention. Until a caller-controlled key and scope are explicitly implemented and tested, new reducers must not introduce stable identifier tokens intended for cross-artifact, cross-session, or cross-export correlation. Redaction must not change non-sensitive semantic conclusions within one analysis. Raw restricted values must not appear in exported findings.
- **Consequences:** Framework v1 records the policy boundary but does not add a token API or runtime abstraction. The Store pilot must define the required equality scope before changing its existing redaction implementation.
- **Executable invariants:** Same-scope redaction preserves intended equality; different scopes do not accidentally create equality; export/redaction does not alter non-sensitive reducer conclusions; restricted values are absent from export.
