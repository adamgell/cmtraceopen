# ADR-003: Chronology and terminal-state precedence

- **Status:** Accepted for Framework v1
- **Context:** Input vector order is often an acquisition or serialization detail, not evidence chronology. Later-looking success can belong to another session, family, identity, or ambiguous retry.
- **Decision:** Reducers may use caller order as chronology only when the source contract explicitly defines it. Otherwise use explicit transaction/session sequencing, valid source-native monotonic identifiers, or timestamps whose semantics and normalization are known. Preserve ambiguity for incomparable records. Terminal outcomes require assessable, correctly identified, sufficiently correlated evidence. Retry success may replace failure only when retry linkage is explicit. Unresolved authoritative contradictions become `Conflicting` or `Unknown` rather than an arbitrary winner.
- **Consequences:** Each workload documents its identity boundary, ordering guarantees, retry linkage, and terminal precedence. Framework v1 does not impose one universal state ranking.
- **Executable invariants:** Permuting non-ordered input does not change a result; unrelated success cannot overwrite failure; ambiguous retry cannot silently become success; unresolved authoritative conflict remains conservative.
