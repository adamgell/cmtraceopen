# `client-notification-bgb` source contract

Issue: #479 (discovery slice of #334)

Card: `crates/cmtraceopen-parser/tests/fixtures/sccm/server/advanced_roles/source-cards/client-notification-bgb.json`, version `1.0.0`. The capture contract (basename, roles, path classes, rotation, and limits) is unchanged, so capture manifests and bundle intake keep attesting `1.0.0`. This slice changes only evidence metadata.

Promotion state: `observed`

Evidence status: sanitized lab observation of framing, rotation, role, path, and version. No notification request or terminal outcome has been observed.

This contract describes what server-side `BgbServer.log` evidence looks like and how it may be captured. It adds no parser, reducer, transaction, finding, or correlation. The card stays capture guidance only until a rule-validated promotion with its own implementation issue.

## Observation

One lab primary site server, observed read-only on 2026-09-25:

| Fact | Observation | Source |
| --- | --- | --- |
| Site version | `5.00.9141.1000` | `HKLM\SOFTWARE\Microsoft\SMS\Setup` value `Full Version` (#770) |
| Notification server role | Present | `HKLM\SOFTWARE\Microsoft\SMS\NotificationServer` exists (listener, throttle, and database settings) |
| Management point role | Present, co-located with the site server | `HKLM\SOFTWARE\Microsoft\SMS\MP` exists and has no `Log Directory` value |
| Path class | `siteServerLogs` | `BgbServer.log` and `BgbServer.lo_` are in the site install root's `Logs` directory, not a configured role log root |
| Component | `SMS_NOTIFICATION_SERVER` | Every framed record |
| Coverage window | About 7 days: the rotated file from 2026-09-18, the current file to 2026-09-25 | File contents |
| Online clients | 2 (1 TCP, 1 HTTP) throughout | `Total online clients` records |
| Client notification pushes | None | No record in either file |

Current discovery does not read the `NotificationServer` key, so it never reports a `clientNotificationServer` role. It also treats the co-located management point's root as a site-install fallback, so capture offers `BgbServer.log` only as an operator-declared candidate. Neither is changed here.

## Framing

`BgbServer.log` uses the legacy SMS trace framing, not the CCM `<![LOG[...]LOG]!>` grammar the card previously declared:

```text
<message>~~  $$<SMS_NOTIFICATION_SERVER><MM-DD-YYYY HH:MM:SS.mmm+BIAS><thread=N (0xHEX)>
```

- Auto-detection selects `ParserKind::Simple`. No new parser kind or grammar is needed.
- The catalog records the family as `simple`, which is descriptive only. The SCCM evidence spine (`normalize_ccm_artifact`) carries CCM logical records, so a `simple` card cannot reach `ruleValidated` until an implementation issue adds a Simple-framed evidence path and its tests.
- Each physical line is one record. No multi-line records were observed.
- The trailing `~~` stays in the message text, because the Simple parser trims only whitespace.
- The timestamp is local time with a signed bias in minutes (`+240` in the lab). The parser applies the bias; timestamps are ordered within each file.
- Severity comes only from message text, as the Simple parser does for every source. In the fixtures, the firewall `WARNING:` message is the only warning type observed.

## Rotation and minimum bundle

The minimum bundle is the current `BgbServer.log` plus `BgbServer.lo_`, which matches the card's `current` and `lo_` rotation policy and 4 MiB cap.

- `BgbServer.lo_` ends with one unframed marker line, `<MAXIMUM LOG FILE SIZE REACHED - FILE RENAMED>`. It is a rotation boundary, not a malformed record. The parser keeps it as a record with no component or timestamp.
- Every record in `.lo_` precedes every record in the current file.
- In the lab the rotated file held about 7 days. A bundle without `.lo_` covers only the time since the last rename, and that must be reported as a coverage gap.

## Record classes observed

| Class | Meaning | Notification semantics |
| --- | --- | --- |
| Component start and listener setup | Executive start, TCP and HTTP listeners accepting connections | None |
| Push-task poll | `Retrieving push tasks from database...`, `Get one push message from database.` | The only retrieved message was the server's own `Found simulation message` self-check |
| Online-status accounting | Client counts, resync checks, generated BGB online-status reports; live-data reports (`*.BLD`) were also observed but are not in a fixture | Aggregate only |
| Management point settings refresh | Refresh plus signing and encryption certificate thumbprints | None |
| Firewall health | `WARNING:` for the notification TCP port, with state message `9802` | Server health, not a client failure |
| State message delivery | `STATMSG`, queued state message, `Successfully send state change notification` | Status system delivery, not client notification |

## Stable keys

No stable non-time notification key exists in the observed evidence. Generated report file names (`*.BLD` observed, `*.BOS` fixtured) and state message files (`*.SMX`, fixtured) are random, and state message GUIDs identify status-system deliveries, not client notifications. The correlation policy stays `unvalidated`, and time-only correlation remains forbidden.

## Coverage states

- Absent, denied, capped, and skipped files keep the capture-level coverage states the collector already reports.
- A present log with no push-task record for a client action is **incomplete** notification evidence. It does not show that nothing was sent, or that anything failed.
- A simulation-message poll is a server self-check and must never be read as a client push.
- Firewall and state-message warnings describe server health. They are not notification failures.

## Terminal semantics

Unobserved. A future rule needs a server-side push request for a named client action, followed by an explicit acknowledgement, rejection, or delivery exhaustion, correlated to the client-side log by a validated key. Until then the card cannot create transactions or failure findings.

## Privacy boundary

| Data | Where it appears | Fixture treatment |
| --- | --- | --- |
| Site server host name and FQDN | `STATMSG` `SYS=` and `ISTR` values, `Inbox source is local on` | `SITESERVER`, `SITESERVER.example.invalid` |
| Site code and site database name | `SITE=`, state message `P1`, `CM_<site>` | `PS1`, `CM_PS1` |
| Certificate thumbprints | Management point settings refresh | 40 zeros |
| State message GUIDs | Queued and delivered state messages | Sequential zero GUIDs |
| Site install root | Inbox and report paths | `<siteInstallRoot>` |
| Generated file names | Report and state message files | Sequential placeholders |

Listener ports (`10123`, `443`), process and thread IDs, and timestamps are kept. They are product defaults or runtime values, not lab identity.

The card's privacy classes are `certificateIdentity`, `databaseIdentity`, `deviceIdentity`, `notificationPayload`, and `userIdentity`. The last two are kept because client pushes and logged-on-user reports carry them even though no payload was observed.

## Fixtures

Under `crates/cmtraceopen-parser/tests/fixtures/sccm/server/advanced_roles/client-notification-bgb/`, each with an `expected.json`:

| Fixture | Pins |
| --- | --- |
| `component-start` | Startup framing and listener setup |
| `firewall-warning-state-message` | Warning severity, state message delivery, identity redaction |
| `mp-settings-certificates` | Certificate thumbprint redaction |
| `online-status-report` | Online-status accounting and report generation |
| `rotation-boundary` | `.lo_` rename marker and ordering across rotation |
| `simulation-poll-no-client-push` | A push-task poll that retrieves only the simulation self-check |

The fixtures are real lab lines with identity replaced; no line was synthesized. Each fixture file is named for the file it came from (`BgbServer.log` or `BgbServer.lo_`), and a test checks that against the observed rename time. The raw logs stay on the lab host. `crates/cmtraceopen-parser/tests/sccm_server_bgb_source_contract.rs` checks detection, framing, rotation order, the card inventory, and the sanitized-identity rules.

## Next evidence

1. Capture `BgbServer.log` across an operator-initiated client notification action, with the matching client-side `CcmNotificationAgent.log`. This needs a change on the site server and requires Adam's approval.
2. Validate server-versus-client notification keys with independent sanitized fixtures before defining any correlation.
3. Separately, decide whether discovery should read the `NotificationServer` key and a co-located management point's log root. That belongs to the capture lane (#497), not this contract.
