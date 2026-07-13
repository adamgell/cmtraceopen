# Privacy-Preserving Download Analytics Design

**Status:** Approved for implementation planning

**Date:** 2026-07-13

**Repositories:** `adamgell/cmtraceopen`, `adamgell/static-adamgell`

## Decision Summary

`https://download.cmtraceopen.com/` will become the canonical human download entry point for CMTrace Open. GitHub Releases will remain the storage and delivery origin for every published binary. The new download host will serve the download page and redirect human-selected downloads to their existing GitHub release assets.

The project will collect distribution analytics only. The running application will not send usage, device, crash, behavioral, identity, or download-attribution telemetry to the new service. Stable and nightly update checks and updater payloads will continue to use GitHub directly.

The system has three coordinated parts:

1. A permanent daily snapshot of GitHub release-asset download counters.
2. Explicit classification of manual downloads, mixed manual/update downloads, updater-only traffic, and supporting files.
3. A first-party download site and aggregate redirect counter at `download.cmtraceopen.com`.

## Goals

- Make `download.cmtraceopen.com` the default destination presented to people looking for CMTrace Open downloads.
- Preserve GitHub Releases as the public, auditable binary origin and fallback.
- Build a permanent daily history from GitHub's cumulative per-asset `download_count` values.
- Report downloads by release, channel, platform, architecture, package type, and delivery role.
- Attribute aggregate clicks from project-controlled entry points without tracking people.
- Preserve replaced nightly-asset counters before their GitHub asset IDs disappear.
- Keep the no-login and no-runtime-telemetry promises simple and accurate.

## Non-Goals

- Counting installations, active users, unique users, devices, retention, uninstalls, feature use, or crashes.
- Identifying or correlating downloaders.
- Storing IP addresses, user-agent strings, cookies, fingerprints, full referrers, or persistent identifiers.
- Proxying binary bytes through Cloudflare.
- Replacing or removing GitHub release assets.
- Routing the application updater through `download.cmtraceopen.com`.
- Treating update-manifest checks as downloads or active-user telemetry.

## System Boundaries

### `adamgell/cmtraceopen`

This repository owns release production and the authoritative GitHub snapshot collector. It will contain:

- Asset classification logic and exhaustive behavior tests.
- A scheduled and manually dispatchable GitHub Actions workflow.
- A collector that enumerates every published release and asset through the GitHub API.
- Permanent snapshot data on a dedicated `download-metrics` branch rather than daily commits on `main`.
- README and release-workflow changes that direct human users to the canonical download site.
- Public wording that distinguishes distribution counts from application telemetry.

### `adamgell/static-adamgell`

This repository owns the human download experience and Cloudflare Worker. It will contain:

- The static assets currently used by `adamgell.com/cmtraceopen/`, promoted to the new canonical host.
- A Worker route that validates an asset ID, records an aggregate event, and redirects to GitHub.
- Stable and nightly asset selection using the public GitHub API.
- Source labels for project-controlled links.
- A legacy redirect from `adamgell.com/cmtraceopen/` to the canonical host.

### Cloudflare

Cloudflare will provide the `download.cmtraceopen.com` custom hostname, Worker runtime, static assets, metadata cache, and aggregate analytics dataset. It will not host the release binaries.

## Canonical Download Experience

### Root page

`https://download.cmtraceopen.com/` will serve the branded builds page rather than immediately redirecting elsewhere. It will show:

- The latest stable release with a prominent recommended Windows x64 download.
- Other stable Windows formats and architectures.
- macOS and Linux packages.
- Current nightly packages in a clearly separated section.
- A direct link to the corresponding GitHub release as a transparent fallback.

The page's canonical URL will be `https://download.cmtraceopen.com/`.

### Asset route

Human-facing asset buttons will use this shape:

```text
https://download.cmtraceopen.com/asset/<github-asset-id>/<readable-filename>?source=<allowlisted-source>
```

The numeric GitHub asset ID is authoritative. The readable filename is cosmetic and must match the resolved asset before the event is counted.

The Worker will:

1. Validate the route and numeric asset ID.
2. Resolve the asset through GitHub's public release-asset API.
3. Verify that the asset belongs to `adamgell/cmtraceopen` and that its download URL is an expected GitHub Releases URL.
4. Verify or canonicalize the readable filename.
5. Classify the asset.
6. Write an aggregate event containing only approved dimensions.
7. Return an HTTP `302` to the asset's existing `browser_download_url`.

The redirect response will not be browser-cached. GitHub metadata may be cached separately at the edge to protect API availability and rate limits.

An analytics write failure will not block a verified download. An asset-validation failure will never redirect to an arbitrary target.

## Published GitHub Assets

Published assets will not be re-uploaded, renamed for analytics, or proxied. A redirected request still downloads from GitHub, so GitHub's native asset counter continues to increase.

GitHub's generated attachment links cannot be replaced. Downloads made directly from the GitHub Releases page will therefore bypass first-party attribution but remain included in GitHub's authoritative totals.

To make the branded domain the majority path:

- The README's primary download call to action will point to `download.cmtraceopen.com`.
- The repository homepage/download references will point to the canonical host where appropriate.
- Future stable release descriptions will begin with a prominent canonical download link.
- The current stable and nightly release descriptions will receive the same link once during rollout.
- `cmtraceopen.com` product content will use the branded download host for its primary download action.
- `adamgell.com/cmtraceopen/` will permanently redirect to the new root page.
- Documentation and other project-controlled download links will be updated.

The attached GitHub files remain visible as a fallback for transparency and resilience.

## Asset Classification

Every observed asset must have exactly one delivery role. Unknown names remain visible in reports but do not silently enter headline download totals.

### `manual-only`

Assets not referenced by the Tauri updater and intended for a person or deployment system to select directly:

- Full portable `.exe`
- Lite portable `.exe`
- `.msi`
- `.dmg`
- `.deb`
- `.rpm`
- `.AppImage`

These form the cleanest headline distribution metric.

### `mixed-manual-update`

- Windows `*-setup.exe`

The current stable and nightly updater manifests reference NSIS setup executables. Their GitHub counters can therefore contain both manual setup downloads and accepted application updates. They must be reported separately and never presented as clean manual downloads.

### `updater-only`

- `latest.json`
- macOS `*.app.tar.gz`
- Signatures belonging specifically to updater payloads

Manifest requests must not be treated as active users. Updater payload downloads may be reported as aggregate update deliveries, separate from manual distribution.

### `supporting-file`

- SBOM files
- Detached signatures not already assigned to updater-only
- Other verification metadata

### `unknown`

Any unmatched asset. Unknowns fail classification tests until deliberately categorized.

## GitHub Snapshot Collector

The collector will run daily after UTC midnight and support `workflow_dispatch`. It will enumerate all releases with pagination and record one row per asset per snapshot.

Each row will include:

- Snapshot timestamp in UTC
- Release ID, tag, channel, publication timestamp, and prerelease state
- Asset ID, filename, creation timestamp, update timestamp, size, and content type
- Current cumulative `download_count`
- Platform, architecture, package type, and delivery role
- Whether the asset is current, replaced, or deleted relative to adjacent snapshots

Derived reports will calculate daily deltas by asset ID. Negative deltas are invalid and must surface as data-quality errors rather than being normalized away.

Snapshot history will live on a dedicated public `download-metrics` branch. That branch will contain append-only dated snapshots plus compact latest CSV and JSON reports. The collector must preserve the last observation of an asset that later disappears, which is essential for mutable nightly releases.

The first snapshot establishes a cumulative baseline. GitHub does not expose historical download dates, so daily history before the first snapshot cannot be reconstructed.

## Aggregate Redirect Events

The Worker analytics event may contain only:

- Automatic event timestamp
- GitHub asset ID
- Release tag and channel
- Asset filename
- Platform
- Architecture
- Package type
- Delivery role
- Allowlisted source label
- Count value

Initial source labels are:

- `download-home`
- `github-readme`
- `github-release`
- `cmtraceopen-product`
- `legacy-builds-page`
- `project-docs`
- `unknown`

User-provided arbitrary source strings will not be stored. Source labels are campaign-level project locations, not identifiers.

The implementation must not read request IP addresses, user-agent headers, cookies, browser fingerprints, or full referrers for analytics. It must not set analytics cookies.

## Reporting Semantics

The two data sources answer different questions:

- **GitHub asset snapshots:** total observed asset deliveries from all paths, including direct GitHub links, branded redirects, external links, package managers, and updater traffic according to classification.
- **First-party redirect events:** aggregate intent from entry points controlled by the project.

The difference between the two is not a conversion rate. Direct GitHub traffic and updater deliveries make the populations intentionally different.

Headline reporting will prioritize:

1. Manual-only downloads and daily change.
2. Mixed manual/update downloads as a separate number.
3. Updater payload deliveries as a separate number.
4. Supporting-file requests outside adoption totals.
5. Branded-host clicks by allowlisted source.

## Privacy Wording

The project will publish wording equivalent to:

> CMTrace Open requires no account and sends no analytics, usage, device, crash, or behavioral telemetry when it runs. GitHub provides aggregate release-asset download counts. Our download website records aggregate uses of download links without storing IP addresses, cookies, user-agent strings, fingerprints, or persistent identifiers. The application never sends data to this analytics system.

The implementation and tests must remain consistent with this statement.

## Failure Handling

- If GitHub release discovery fails, the page will show a clear error and a direct link to GitHub Releases.
- If a Worker asset lookup fails, it will return a safe not-found response without counting or redirecting.
- If Analytics Engine is unavailable, a validated download will continue to GitHub without blocking the user.
- If a nightly asset is replaced, the next page refresh will use its new asset ID and the daily collector will retain the prior asset's final observation.
- If an asset is unknown to the classifier, it will be shown in diagnostic output but excluded from headline totals until classified.
- Scheduled snapshot failures will produce a failed workflow and preserve the last valid reports.

## Security Controls

- Asset redirects accept only numeric GitHub asset IDs.
- Resolved assets must belong to the expected repository.
- Redirect targets must use HTTPS and the expected GitHub Releases host/path.
- The Worker is not a general-purpose open redirect.
- No GitHub write token is exposed to browser code.
- Any token used for scheduled snapshot commits receives only the minimum repository permissions.
- Source labels and filenames are validated against resolved metadata before storage.

## Verification Strategy

### Asset classification

Tests will explicitly cover every current filename family and edge case:

- Full versus Lite portable EXE
- x64 versus ARM64 Windows packages
- NSIS setup executables as mixed traffic
- macOS DMG versus updater archive
- Linux formats
- `latest.json`, signatures, and SBOMs
- Unknown names
- Nightly names containing date, run number, and commit suffix

### Snapshot collector

Fixture-driven tests will cover pagination, cumulative deltas, asset replacement, deletion, zero counts, unknown assets, and invalid negative deltas.

### Worker

Tests will prove:

- A verified asset redirects to the exact GitHub URL.
- The analytics payload contains only allowed fields.
- Request headers and identifiers never enter the analytics payload.
- Arbitrary URLs and cross-repository asset IDs are rejected.
- Unapproved source values become `unknown`.
- Analytics failure does not prevent a verified download.
- GitHub lookup failure does not create an event.

### Download site

Tests will verify stable and nightly rendering, canonical URLs, source labels, accessible download controls, error fallback, and that updater-only metadata is not presented as a normal download.

## Rollout

1. Add classification and the GitHub snapshot collector without changing public links.
2. Capture and validate the initial cumulative baseline.
3. Build and test the Worker and static download site on a non-canonical preview route.
4. Configure `download.cmtraceopen.com` and verify TLS, DNS, redirect validation, and aggregate event shape.
5. Publish the privacy wording.
6. Change the README, current release descriptions, product site, legacy builds page, and project documentation to favor the canonical host.
7. Observe GitHub snapshot deltas and branded-host events for at least one full day.
8. Keep GitHub direct links available as the resilient fallback.

## Acceptance Criteria

- `download.cmtraceopen.com` serves the canonical stable and nightly download page.
- A human-selected asset records an identifier-free aggregate event and downloads from the existing GitHub asset URL.
- GitHub's native asset counter continues to increase for redirected downloads.
- The running application and updater never contact the new host.
- Daily snapshots survive nightly asset replacement and do not create commits on `main`.
- Manual-only, mixed, updater-only, supporting, and unknown assets remain separately reportable.
- No implementation surface stores IP addresses, user agents, cookies, fingerprints, full referrers, or persistent user/device identifiers.
- Primary project-controlled download links favor the canonical branded host.
