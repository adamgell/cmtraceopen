# SCCM site-database export v1

This is an explicit, operator-supplied coverage contract. Submit one JSON document directly to `assess_sccm_site_database_export`; it is not discovered through server intake and it never opens, queries, or authenticates to a database.

## Contract limits

- Accept at most 1,048,576 input bytes before JSON parsing.
- Accept one `snapshot` object for `captured` or `partial`; `accessDenied` requires `snapshot: null`.
- Require schema version `1`, contract ID `sccm-site-database-export`, intent `captureMore`, and export profile `sccm-site-database-export-v1`.
- Reject duplicate keys recursively before typed deserialization. Unknown properties are rejected at every object level.
- Require UTC timestamps normalized with `Z`; export completion cannot precede export start.

## Privacy and public projection

| Class | Accepted input | Public output |
| --- | --- | --- |
| Database and site identity | Fixed-prefix opaque handles only | Never returned |
| Export provenance | Fixed profile ID and opaque exporter host handle | Never returned |
| Device, package, and deployment data | Bounded aggregate counts only | Counts never returned |
| User identity | Not represented | Never available |

The schema contains no field for raw database identity, SQL text, connection metadata, credentials, rows, resource identifiers, package names, deployment identifiers, collection identifiers, user identity, or site names. Unsupported fields stop assessment.

## Integrity binding

The sender computes SHA-256 over `serde_json::to_vec` of an object with these fields, in exactly this order: `schemaVersion`, `contractId`, `intent`, `captureState`, `authorization`, `provenance`, `snapshot`. The `integrity` object is excluded from the material. The digest is lowercase hexadecimal. The validator compares the public integrity digests using ordinary deterministic byte equality after syntax validation; this digest is an integrity value, not a secret.

## Coverage outcome and stop conditions

The public result contains only contract ID, schema version, a coverage state and coarse gate code, plus `coverageOnly`. Captured, partial, and access-denied inputs are coverage states; they are never semantic evidence and cannot create findings, transactions, collection requests, parser output, reducer output, or correlation data.

Stop with a non-semantic error for oversized, malformed, duplicate, unsupported-version, unknown-profile, unauthorized, inconsistent, privacy-violating, invalid-handle, invalid-time, invalid-count, multiple-snapshot, or integrity-mismatched input. Do not retry through server logs, discover a database, request credentials, invoke native APIs, or perform live database work.

## CAPTURE-MORE boundary

The SQL database source card remains deferred. Synthetic contract fixtures alone are not sanitized production provenance, a source-version policy, or evidence for semantic admission. Promotion requires reviewed fixtures, sanitized operator authorization/provenance observation, privacy approval, source-version policy, exact correlation keys, incomplete/error scenarios, a named implementation issue, and a separately tested reducer.
