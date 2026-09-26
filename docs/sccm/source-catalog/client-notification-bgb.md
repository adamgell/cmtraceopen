# `client-notification-bgb` source contract

Issue: #479 (discovery slice of #334)

Card: `crates/cmtraceopen-parser/tests/fixtures/sccm/server/advanced_roles/source-cards/client-notification-bgb.json`, version `1.0.0`. The capture contract (basename, roles, path classes, rotation, and limits) is unchanged, so capture manifests and bundle intake keep attesting `1.0.0`. This slice changes only evidence metadata.

Promotion state: `observed`

Evidence status: sanitized lab observation of framing, rotation, role, path, and version, plus one operator-initiated client notification observed end to end on both sides. No failure outcome has been observed.

This contract describes what server-side `BgbServer.log` evidence looks like and how it may be captured. It adds no parser, reducer, transaction, finding, or correlation. The card stays capture guidance only until a rule-validated promotion with its own implementation issue.

## Observation

One lab primary site server on 2026-09-25, observed read-only except for one operator-initiated client notification that Adam approved (PushID 13, a machine policy request to the site server's own client). Repeating or extending that capture needs Adam's approval again.

| Fact | Observation | Source |
| --- | --- | --- |
| Site version | `5.00.9141.1000` | `HKLM\SOFTWARE\Microsoft\SMS\Setup` value `Full Version` (#770) |
| Notification server role | Present | `HKLM\SOFTWARE\Microsoft\SMS\NotificationServer` exists (listener, throttle, and database settings) |
| Management point role | Present, co-located with the site server | `HKLM\SOFTWARE\Microsoft\SMS\MP` exists and has no `Log Directory` value |
| Path class | `siteServerLogs` | `BgbServer.log` and `BgbServer.lo_` are in the site install root's `Logs` directory, not a configured role log root |
| Component | `SMS_NOTIFICATION_SERVER` | Every framed record |
| Coverage window | About 7 days: the rotated file from 2026-09-18, the current file to 2026-09-25 | File contents |
| Online clients | 2 (1 TCP, 1 HTTP) throughout | `Total online clients` records |
| Client notification pushes | None in 7 days of passive history; one operator-initiated push (PushID 13) on 2026-09-25, approved by Adam | `BgbServer.log`, and the client's `CcmNotificationAgent.log` |
| Paired client | The site server's own ConfigMgr client, version `5.00.9141.1011`, logging to `C:\Program Files\SMS_CCM\Logs` (co-located with the management point) | `HKLM\SOFTWARE\Microsoft\SMS\Mobile Client` value `SmsClientVersion`, and the console |

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
| Push-task poll | `Retrieving push tasks from database...`, `Get one push message from database.` | Without a pending action, the only retrieved message is the server's own `Found simulation message` self-check |
| Push-task delivery | `Starting to send push task (PushID TaskID TaskGUID TaskType TaskParam) to N clients`, `Finished sending push task (PushID TaskID) to N clients` | The server-side request for one client action |
| Task status report | `Generated BGB task status report … (PushID ReportedClients FailedClients)` | The server-side terminal outcome for that push |
| Online-status accounting | Client counts, resync checks, generated BGB online-status reports; live-data reports (`*.BLD`) were also observed but are not in a fixture | Aggregate only |
| Management point settings refresh | Refresh plus signing and encryption certificate thumbprints | None |
| Firewall health | `WARNING:` for the notification TCP port, with state message `9802` | Server health, not a client failure |
| State message delivery | `STATMSG`, queued state message, `Successfully send state change notification` | Status system delivery, not client notification |

## Stable keys

The observed push carries an exact non-time key on both sides: server `PushID`, `TaskID` and `TaskGUID` in `Starting to send push task`, and client `pushid`, `taskid` and `taskguid` in the `BgbAgent` record `Receive task from server`. In the one observed push all three matched exactly, and the task type matched. The task status report repeats the `PushID`.

These are key **candidates**. One matched pair shows the key exists but not that it is collision-safe (for example, whether `PushID` restarts), so the correlation policy stays `unvalidated`. Time only corroborates the order (the client logged receipt 50 ms after the server started sending) and is never the key.

Generated report file names (`*.BLD` observed; `*.BOS` and `*.BTS` fixtured) and state message files (`*.SMX`, fixtured) are random, and state message GUIDs identify status-system deliveries, not client notifications.

## Coverage states

- Absent, denied, capped, and skipped files keep the capture-level coverage states the collector already reports.
- A present log with no push-task record for a client action is **incomplete** notification evidence. It does not show that nothing was sent, or that anything failed.
- A simulation-message poll is a server self-check and must never be read as a client push.
- Firewall and state-message warnings describe server health. They are not notification failures.

## Terminal semantics

Success is observed; failure is not.

- **Request:** `Starting to send push task … to N clients`, then `Finished sending push task … to N clients`.
- **Client receipt:** `Receive task from server with pushid=…, taskid=…, taskguid=…` in the client's `CcmNotificationAgent.log` (component `BgbAgent`, CCM framing).
- **Terminal outcome:** `Generated BGB task status report … (PushID: N ReportedClients: R FailedClients: F)`. The observed push reported `ReportedClients: 1 FailedClients: 0`, about 29 seconds after sending.
- **Unobserved:** any report with `FailedClients` above zero, and any rejection or delivery-exhaustion record. A failure rule cannot be written from this evidence.

The card stays capture guidance only: no transactions or failure findings until failure evidence and a collision-safe key exist and a rule-validated promotion has its own implementation issue.

## Privacy boundary

| Data | Where it appears | Fixture treatment |
| --- | --- | --- |
| Site server host name and FQDN | `STATMSG` `SYS=` and `ISTR` values, `Inbox source is local on` | `SITESERVER`, `SITESERVER.example.invalid` |
| Site code and site database name | `SITE=`, state message `P1`, `CM_<site>` | `PS1`, `CM_PS1` |
| Certificate thumbprints | Management point settings refresh | 40 zeros |
| State message GUIDs | Queued and delivered state messages | Sequential zero GUIDs |
| Site install root | Inbox and report paths | `<siteInstallRoot>` |
| Generated file names | Report, task status, and state message files | Sequential placeholders |
| Push task GUID | Server `TaskGUID` and client `taskguid` | The same zero GUID on both sides, so the key match survives sanitization |
| Client IP address and subnet | Client `BgbAgent` keep-alive records | Not fixtured |

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
| `push-task-delivered` | One push task on the server and its receipt on the client, linked by exact `PushID`, `TaskID` and `TaskGUID`, and closed by the task status report |
| `rotation-boundary` | `.lo_` rename marker and ordering across rotation |
| `simulation-poll-no-client-push` | A push-task poll that retrieves only the simulation self-check |

The fixtures are real lab lines with identity replaced; no line was synthesized. Each fixture file is named for the file it came from (`BgbServer.log`, `BgbServer.lo_`, or the client's `CcmNotificationAgent.log`), and a test checks the server files against the observed rename time. The raw logs stay on the lab host. `crates/cmtraceopen-parser/tests/sccm_server_bgb_source_contract.rs` checks detection, framing, rotation order, the card inventory, and the sanitized-identity rules.

## Next evidence

1. A push whose status report shows `FailedClients` above zero (for example, a notification to an offline client), so a failure outcome is observed. This is a site server action and needs Adam's approval.
2. A second push to a different client, so the key can be shown collision-safe before the correlation policy is validated. Also a site server action.
3. Separately, decide whether discovery should read the `NotificationServer` key and a co-located management point's log root. That belongs to the capture lane (#497), not this contract.
