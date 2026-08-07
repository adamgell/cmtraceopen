# ADR-001: Evidence strength constrains finding confidence

- **Status:** Accepted for Framework v1
- **Context:** Reducers currently expose conclusion confidence, while source authority and evidence quality are separate concerns. Repetition cannot promote weak evidence into authoritative evidence.
- **Decision:** Keep `IntuneFindingConfidence` as the public conclusion projection. Reducer contracts must classify evidence strength separately as `Authoritative`, `Strong`, `Corroborating`, `Weak`, or `Untrusted`. Evidence strength may constrain confidence, but confidence must never be used as a substitute for source authority. Non-assessable evidence cannot produce a terminal conclusion.
- **Consequences:** Workload reducers retain domain-specific confidence rules. Framework v1 adds no numeric score and no universal reducer. A later shared helper is justified only by a concrete Store test and must preserve this separation.
- **Executable invariants:** Weak evidence cannot become authoritative through duplication; untrusted or non-assessable evidence cannot produce high-confidence terminal success/failure; coverage gaps cannot raise confidence.
