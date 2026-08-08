# SCCM client-management fixture corpus

This directory contains synthetic, proposal-only contracts for issue #326.
Nothing here is a production extraction profile or evidence that a source was
validated on Windows. `CoManagementHandler.log`, `Scripts.log`, and
`CcmNotificationAgent.log` are admitted only for this deterministic test
profile. The sanitized `SCClient_SYNTHETIC_*.log` and
`SCNotify_SYNTHETIC_*.log` names are deliberately marked
`candidateUnsupported`; their records must not be parsed into operational
findings.

Every semantic record contains `SYNTHETIC FIXTURE`. All identities, handles,
paths, versions, and signals are fictional. Physical fragments remain separate
through artifact IDs, relative paths, rotation state, and path fingerprints.
