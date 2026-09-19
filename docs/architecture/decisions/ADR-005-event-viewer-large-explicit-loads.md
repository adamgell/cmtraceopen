# ADR-005: Who owns a very large explicit event load

- **Status:** Proposed — recorded as the resolution of issue #635. Confirm at merge.
- **Context:** The Event Viewer workspace bounds the automatic load at
  `AUTO_LOAD_MAX_EVENTS` (2,000 events per channel) and says so on screen when a
  channel comes back at the bound. That bound is deliberately not applied to the
  explicit Load, because a whole channel must stay reachable by an operator who
  asks for it. The explicit path therefore remains unbounded, and on the
  Security log measured for the epic (239,704 events in twenty-four hours, 318
  seconds to read) it is a multi-minute read whose records are then held on the
  client. Issue #635 asks who owns such a load.

## Decision

**The frontend owns explicit loads.** The records are fetched and held in the
store, exactly as today, and the read stays bounded by two affordances this
decision adds: a stop control that cancels the in-flight read, and a
cancelled-load coverage gap that keeps the partial result honest.

Backend-owned paging for very large explicit loads is **deferred**, not
forgotten: it is the right design when evidence says so, and the criteria below
are the trigger. It is a design change, not a configuration change, and it must
be designed on top of a Preview whose acceptance matrix has run.

## Why not the backend-owned path now

1. **Every interaction is over the in-store record set.** Filter, group, sort,
   export, unified-timeline merge, and marker selection all read the records the
   store holds. Backend ownership of the records means backend ownership of the
   query surface — the workspace's read model becomes a paging interface. That
   is a redesign, not a transport swap, and rebuilding an unvalidated Preview
   around it trades a working product for speculative complexity.
2. **The transport problem is already solved.** The live read streams bounded
   batches with sequence numbers, gap detection, and reconciliation
   (`evtx-record-batch`, `reconcileStreamedResult`); the 318-second Security
   read already shows progress throughout and merges progressively instead of
   arriving as one monolithic reply.
3. **The memory risk is measured, not assumed.** The worst case observed today
   is ~240,000 records per explicit load, comfortably inside the WebView's
   budget, and the epic's real-world validation is exactly the test that will
   find a channel that is not. A channel that genuinely cannot be held by the
   client is the trigger for the deferred design, not a premise to assume.

## What changes now

- **Stop control.** A new `evtx_cancel_channel_query` command sets a per-request
  cancel flag; the channel read loop checks it between batches and stops,
  returning the partial scan with an honest gap. The UI's loading state becomes
  a Stop button while a load runs.
- **Cancelled-load coverage.** A cancelled scan surfaces as a
  `cancelled`-kind coverage gap ("operator stopped the load after N events"), so
  a stopped read can never read as a complete one, and the channel is not marked
  loaded, so the operator can Load it again.

## Scope ruling for the deferred path

When the backend-owned path is built (see criteria), it must be a **parallel
read session** — a new backend-owned transport — never an inversion of the
export session machinery. Export sessions are a WebView-to-backend upload ending
in a redacting publication whose boundary is governed by ADR-004 and its
revision 1. A read path and a publication path sharing one session type would
couple the read of a channel to the publication boundary this repository has
deliberately separated, and that boundary must not be weakened.

## Revisit criteria

Design the backend-owned path when any of these is observed:

- The installed-and-native acceptance matrix (epic #539) records a real channel
  that a client-side explicit load cannot hold, with numbers.
- A real operator reports the explicit load as unusable after the stop control
  and honest gap are in place, with numbers.

## Consequences

- The epic ledger item "Backend-owned paging for very large explicit loads
  (tracked in #635)" is resolved as deferred with these criteria.
- Privacy and release-channel work is untouched; nothing here couples to the
  ADR-004 redaction scope or to channel/release work.
