# CMTrace Open download metrics collector

This isolated command snapshots the cumulative download counters exposed for
CMTrace Open GitHub release assets. GitHub counts are cumulative requests, not
users or installations. They also are not active-user, unique-user, or
conversion measurements.

## Local use

Use Node.js 22 or newer, install the locked dependencies, and choose a dedicated
output directory outside this repository root and its `.git` directory:

```bash
npm ci
npm run check
npm test
npm run collect -- --output "$(mktemp -d)"
```

To calculate changes from a particular valid prior report, add
`--previous /path/to/reports/latest-assets.json`. When omitted, the collector
uses `<output>/reports/latest-assets.json` if that file exists. `GITHUB_TOKEN`
is optional for local reads and, when present, is used only as GitHub API
authorization.

The command writes these deterministic artifacts beneath the selected output
directory:

- `snapshots/YYYY/MM/<UTC timestamp>.json`
- `reports/latest-assets.json`
- `reports/latest-assets.csv`
- `reports/summary.json`

The first snapshot is a cumulative baseline; it does not reconstruct historical
daily activity. Direct GitHub download traffic and updater traffic remain
included in GitHub's asset counters. Negative deltas fail collection rather
than being rewritten or hidden. Failed API, validation, or write operations
leave the last valid report in place.

## Workflow status

The dedicated workflow records only `snapshots/` and `reports/` on the
`download-metrics` branch. It can push only `HEAD:download-metrics`, never
`main`. The workflow has not been activated or pushed during local development.
