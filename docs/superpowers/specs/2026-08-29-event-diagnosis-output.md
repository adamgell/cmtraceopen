# Event diagnosis output repair

## Problem

The Windows 11 ARM64 Event Log workspace can load thousands of records successfully and still
present an unusable first screen. The diagnosis card currently renders source-wide evidence,
correlations, coverage gaps, findings, and event details without a collapsed or bounded container.
Ordinary Application and System events also create one diagnosis coverage gap per event merely
because their provider family is not one of the device-management families, and the timeline adds
another gap when an event has no explicit correlation key. Finally, a provider message-resource
failure is reported as a rejected record even though the record itself is retained.

These are product semantics and layout defects. They are not an ARM64 rendering defect.

## Required behavior

### Compact diagnosis surface

- The diagnosis card shows the headline and accurate summary counts while collapsed by default.
- Detailed findings, grouped coverage gaps, correlations, and error-token event details are behind
  one explicit disclosure control.
- Expanded content has its own bounded vertical scroll region. It cannot displace the timeline and
  event grid beyond the workspace viewport.
- The UI never renders the summary-wide raw evidence collection as one paragraph.
- A finding appears once. Event details do not repeat findings already present in
  `DiagnosisSummary.findings`.
- Event details are limited to events with resolved or unresolved error tokens. Evidence alone does
  not make every loaded event notable.
- Identical coverage gaps are grouped by source, state, and detail and display an occurrence count.
- Findings, grouped gaps, correlations, and error-token event details each have a fixed render cap
  with an explicit omitted-count message.
- The finding count shown in both the header and overview is the actionable finding count, excluding
  `coverageGap` findings. Coverage has its own count.

### Filter-scoped diagnosis

- The diagnosis request receives `visibleRecords` and the matching `visibleTimeline` after the
  current channel, level, time, event-ID, search, quick-filter, and visible-column filters are
  applied.
- Source acquisition coverage remains attached because filters cannot repair unread or unavailable
  source data.
- A stale full timeline must not be mixed with a newer visible record set.

### Neutral ordinary events

- An event whose family is `Other` remains available as evidence and may still expose parsed error
  tokens, but being outside the device-management diagnosis families is not itself a finding or a
  coverage gap.
- A timeline observation with a known machine but no explicit or secondary correlation keys simply
  has no causal edge. That normal lack of a relationship is not a coverage gap.
- Specific missing/malformed identities, conflicting identities, fan-out limits, truncation, and
  producer-supplied gaps remain explicit.

### Provider message-resource coverage

- Failure to open publisher metadata and failure to format a provider message are distinct stages.
- The provider name, stage, Windows error code, and source channel are retained in a structured
  provider coverage gap.
- Provider lookup failures are deduplicated per provider and stage within a channel scan.
- The event record is still delivered with its XML/EventData fallback message.
- Provider coverage gaps use `EvtxCoverageGapKind::Provider`; they do not increment `parse_errors`
  and are not reclassified as rejected records.
- True XML/render/record loss continues to increment parse errors and keeps its existing record-loss
  coverage classification.
- Live-tail string diagnostics may be derived from the structured provider gap, but the batch query
  path must not recover structure by parsing an operator-facing string.

## Verification boundary

Portable frontend and Rust tests must pass on macOS. The final executable must then be built in the
already-running Windows 11 ARM64 Parallels guest through Computer Use, launched only after the
required action-time confirmation, and checked against a real Application/System load. Acceptance
requires a compact first screen, reachable timeline and event grid, non-inflated coverage counts,
and retained provider-specific diagnostics when Windows cannot resolve a message resource.
