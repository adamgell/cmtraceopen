# Synthetic Software Update Point corpus

This directory is the preparation-only fixture corpus for issue #330. Every
record is synthetic and uses opaque `safe:` handles plus `SYNTHETIC://` path
provenance. The raw `.log` files remain CCM transport and are consumed through
the shared SCCM logical-record normalizer.

The matrix covers successful synchronization, WCM configuration failure, WSUS
health failure, retry/deferred synchronization, metadata failure, SUP setup
failure, optional WSUS coverage skipped, an unrelated client update key,
rotation-split fragments, and incomplete access/absence coverage.

These fixtures do not assert a production reducer, live Windows collection,
role absence, client impact, or cross-side causality. Production work remains
dependent on the reviewed #318 and #335 contracts; #333 owns any later
cross-side correlation.
