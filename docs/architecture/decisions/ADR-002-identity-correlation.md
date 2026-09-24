# ADR-002: Identity and correlation strength

- **Status:** Accepted for Framework v1
- **Context:** Display names, timestamps, and shared channels are insufficient to establish that observations belong to one workload transaction.
- **Decision:** Correlation is an explicit decision with a reason. Exact transaction/session keys, exact workload/package identity, and explicit shared keys may be strong; stable secondary identity may be moderate; composite name/version is weak/candidate; display name alone is insufficient; timestamp proximity alone never creates strong correlation or causality. The existing `IntuneObservationContext` remains the provenance/evidence basis.
- **Consequences:** Workload reducers choose the minimum correlation strength required for each transition. They must not promote weak or untyped fields locally into shared semantic authority. Framework v1 adds no universal correlation engine.
- **Executable invariants:** Weak identity cannot create strong correlation; timestamp proximity alone cannot produce high-confidence causality; unrelated package/session/family observations cannot alter a transaction.
