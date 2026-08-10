# ADR-004: Redaction scope and correlation

> **A revision is proposed and awaiting a ruling:**
> `ADR-004-redaction-scope-revision-1.md`. It decides equality scope and
> ownership, and records a direct contradiction between this document's
> prohibition on stable correlation tokens and what five of six lanes ship.
> This document remains authoritative until that revision is ruled on.

- **Status:** Architecture boundary accepted; token/equality scope provisional
- **Context:** Redaction can preserve or destroy equality used for diagnostic correlation. Independent workload token algorithms can create accidental cross-artifact or cross-session joins.
- **Decision:** Redaction is a shared architectural contract, not a workload-local convention; that boundary is accepted. The actual token algorithm, caller-controlled key, equality scope, and cross-artifact/session/export behavior remain provisional until they are explicitly defined and tested. Until then, new reducers must not introduce stable identifier tokens intended for cross-artifact, cross-session, or cross-export correlation. Redaction must not change non-sensitive semantic conclusions within one analysis. Raw restricted values must not appear in exported findings.
- **Consequences:** Framework v1 records the architecture boundary but does not add a token API or runtime abstraction. The Store pilot must define and test the required equality scope before changing its existing redaction implementation.
- **Executable invariants:** Same-scope redaction preserves intended equality; different scopes do not accidentally create equality; export/redaction does not alter non-sensitive reducer conclusions; restricted values are absent from export.
