# CMTrace Open Download Distribution and Analytics Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the matching Signal Room stable-download center, identifier-free aggregate redirect counting, and daily GitHub release-asset snapshots while leaving application runtime behavior and updater endpoints unchanged.

**Architecture:** Extend `/Users/Adam.Gell/repo/static-adamgell/cmtraceopen-site` with a Cloudflare Worker that dispatches by hostname, serves normalized stable-release data, validates numeric GitHub asset IDs, writes one allowlisted Analytics Engine data point, and redirects the browser to GitHub. Add an isolated TypeScript collector under `/Users/Adam.Gell/repo/cmtraceopen/tools/download-metrics` that snapshots cumulative GitHub counters and publishes reports only to a dedicated `download-metrics` branch when the workflow is eventually activated. The Worker and collector share the same pure classification contract and current release fixture.

**Tech Stack:** TypeScript, Astro 7, Cloudflare Workers/Wrangler 4, Workers Static Assets, Workers Analytics Engine, Vitest 4.1 with `@cloudflare/vitest-pool-workers`, Node.js 22 built-in `fetch`, GitHub REST API, GitHub Actions, Playwright.

## Global Constraints

- Keep all development, tests, previews, and commits local; do not push, deploy, attach either domain, edit DNS, mutate a GitHub release, run a GitHub workflow, or open a pull request.
- The running application and Tauri updater must never contact `cmtraceopen.com` or `download.cmtraceopen.com`; existing `latest.json` and updater payload URLs remain direct GitHub URLs.
- Do not read or store request IP addresses, `CF-Connecting-IP`, user-agent headers, cookies, browser fingerprints, full referrers, geolocation, or persistent user/device identifiers.
- Do not set cookies. Send `Referrer-Policy: no-referrer` from the branded site.
- Accept only numeric GitHub asset IDs, resolve them through `repos/adamgell/cmtraceopen/releases/assets/{id}`, and redirect only to HTTPS `github.com/adamgell/cmtraceopen/releases/download/...` URLs.
- A validated asset download must proceed when Analytics Engine is missing or throws; an unverified asset must never count or redirect.
- Allow only these source labels: `download-home`, `github-readme`, `github-release`, `cmtraceopen-product`, `nightly-builds-page`, `project-docs`, `unknown`.
- Describe counts as asset deliveries or download-link selections, never installations, active users, unique users, or conversion rates.
- Preserve `https://adamgell.com/cmtraceopen/` for nightlies and `https://adamgell.com/tools/cmtrace/` for editorial content.
- GitHub remains the source-code, release-record, and binary-delivery origin.
- Daily snapshots go to `download-metrics`, never `main`; the first snapshot is a cumulative baseline and does not invent historical daily counts.
- Use local commits after each task, but never push them without separate authorization.

---

## Cross-Repository File Map

### `/Users/Adam.Gell/repo/static-adamgell/cmtraceopen-site`

- `src/lib/releases/types.ts` — shared release, asset, classification, and source-label types.
- `src/lib/releases/classify.ts` — pure filename classifier and data-driven recommendation rules.
- `src/lib/releases/github.ts` — cached GitHub release/asset resolution and target validation.
- `src/lib/releases/analytics.ts` — the only Analytics Engine event construction function.
- `src/worker/index.ts` — hostname dispatch, API routes, asset redirect, security headers, and asset serving.
- `src/pages/_download/index.astro` — download-center document using shared Signal Room components.
- `src/components/download/PackageChooser.astro` — accessible package shell and error fallback.
- `src/scripts/download-center.ts` — stable-release fetch, filtering, and link creation.
- `src/styles/download.css` — package chooser, tabs, integrity panel, and trust band.
- `analytics/schema.md` — ordered Analytics Engine column mapping and retention caveat.
- `analytics/queries.sql` — sampling-aware aggregate queries by time, package, and source.
- `tests/fixtures/release-assets.json` — current v1.4.0 and nightly filename families.
- `tests/classify.test.ts`, `tests/github.test.ts`, `tests/worker.test.ts`, `tests/download.spec.ts` — contract, security, failure, and browser coverage.

### `/Users/Adam.Gell/repo/cmtraceopen/tools/download-metrics`

- `src/classify.ts` — byte-for-byte copy of the site classifier.
- `src/types.ts` — snapshot/report types.
- `src/github.ts` — paginated release enumeration.
- `src/reconcile.ts` — deltas, replacement/deletion tombstones, and invalid-negative checks.
- `src/report.ts` — JSON/CSV and headline-role summaries.
- `src/collect.ts` — CLI orchestration with injected clock and output directory.
- `tests/fixtures/release-assets.json` — byte-for-byte copy of the shared fixture.
- `tests/classify.test.ts`, `tests/reconcile.test.ts`, `tests/collect.test.ts` — exhaustive local validation.
- `package.json`, `package-lock.json`, `tsconfig.json`, `vitest.config.ts` — isolated toolchain.
- `.github/workflows/download-metrics.yml` — eventual daily/manual collector that commits only to `download-metrics`.

### Existing project-controlled links

- `/Users/Adam.Gell/repo/cmtraceopen/README.md` — stable calls to action use `?source=github-readme`.
- `/Users/Adam.Gell/repo/cmtraceopen/.github/workflows/cmtrace-release.yml` — future release body begins with branded stable link.
- `/Users/Adam.Gell/repo/cmtraceopen/.github/workflows/codesign.yml` — Windows-created release body uses the same link.
- `/Users/Adam.Gell/repo/cmtraceopen/.github/workflows/cmtrace-nightly-signed.yml` — nightly notes point to the retained nightly page, not the stable package chooser.
- `/Users/Adam.Gell/repo/static-adamgell/public/cmtraceopen/index.html` — Nightly Builds header links back to Product and Stable Download.
- `/Users/Adam.Gell/repo/static-adamgell/public/cmtraceopen/app.js` — human asset links use branded numeric-ID redirects with `nightly-builds-page`.
- `/Users/Adam.Gell/repo/static-adamgell/public/cmtraceopen/styles.css` — restrained shared visual cues without changing the page's nightly role.

---

### Task 1: Add the Worker test/build boundary to the product-site package

**Files:**
- Modify: `cmtraceopen-site/package.json`
- Modify: `cmtraceopen-site/wrangler.jsonc`
- Modify: `cmtraceopen-site/tsconfig.json`
- Create: `cmtraceopen-site/vitest.config.ts`
- Create: `cmtraceopen-site/tests/tsconfig.json`

**Interfaces:**
- Produces: `npm run test:worker` and generated `src/worker-configuration.d.ts` types.
- Produces: `Env` bindings `ASSETS: Fetcher` and `DOWNLOAD_EVENTS: AnalyticsEngineDataset`.
- Consumes: `dist/` from the product-site plan.

- [ ] **Step 1: Extend the package scripts and dev dependencies**

Add:

```json
"scripts": {
  "types:worker": "wrangler types src/worker-configuration.d.ts",
  "test:worker": "npm run types:worker && vitest run --config vitest.config.ts"
},
"devDependencies": {
  "@cloudflare/vitest-pool-workers": "0.18.4",
  "vitest": "4.1.10"
}
```

Merge these keys with the existing scripts/dependencies; do not remove product-site commands.

- [ ] **Step 2: Configure one local Worker without production routes**

Update `wrangler.jsonc` to this contract:

```jsonc
{
  "$schema": "./node_modules/wrangler/config-schema.json",
  "name": "cmtraceopen-product",
  "main": "src/worker/index.ts",
  "compatibility_date": "2026-07-13",
  "assets": {
    "directory": "./dist",
    "binding": "ASSETS",
    "run_worker_first": true,
    "html_handling": "force-trailing-slash",
    "not_found_handling": "404-page"
  },
  "analytics_engine_datasets": [
    { "binding": "DOWNLOAD_EVENTS", "dataset": "cmtraceopen_download_events" }
  ],
  "observability": { "enabled": false }
}
```

Do not add `routes`, `custom_domain`, `account_id`, or secrets.

- [ ] **Step 3: Configure Cloudflare Vitest**

Use the official pool configuration:

```ts
import { cloudflareTest } from "@cloudflare/vitest-pool-workers";
import { defineConfig } from "vitest/config";

export default defineConfig({
  plugins: [cloudflareTest({ wrangler: { configPath: "./wrangler.jsonc" } })],
  test: { include: ["tests/**/*.test.ts"] },
});
```

`tests/tsconfig.json` must include `@cloudflare/vitest-pool-workers/types` and `../src/worker-configuration.d.ts`.

- [ ] **Step 4: Install, generate types, and verify configuration**

Run: `cd cmtraceopen-site && npm install && npm run types:worker`

Expected: npm exits 0 and Wrangler generates `src/worker-configuration.d.ts` containing both bindings.

- [ ] **Step 5: Commit locally**

```bash
git add cmtraceopen-site/package.json cmtraceopen-site/package-lock.json cmtraceopen-site/wrangler.jsonc cmtraceopen-site/tsconfig.json cmtraceopen-site/vitest.config.ts cmtraceopen-site/tests/tsconfig.json cmtraceopen-site/src/worker-configuration.d.ts
git commit -m "build: add download Worker test boundary"
```

Do not push.

### Task 2: Implement the exhaustive asset-classification contract

**Files:**
- Create: `cmtraceopen-site/src/lib/releases/types.ts`
- Create: `cmtraceopen-site/src/lib/releases/classify.ts`
- Create: `cmtraceopen-site/tests/fixtures/release-assets.json`
- Create: `cmtraceopen-site/tests/classify.test.ts`

**Interfaces:**
- Produces: `classifyAsset(name: string): AssetClassification`.
- Produces: `recommendationRank(asset: ClassifiedReleaseAsset): number | null`.
- Produces: `normalizeSource(value: string | null): SourceLabel`.

- [ ] **Step 1: Define the exact domain types**

```ts
export const CLASSIFICATION_CONTRACT = "2026-07-13.1" as const;
export type Platform = "windows" | "macos" | "linux" | "cross-platform" | "unknown";
export type Architecture = "x64" | "arm64" | "unknown";
export type Edition = "full" | "lite" | "not-applicable" | "unknown";
export type PackageType = "portable-exe" | "msi" | "nsis-setup" | "dmg" | "deb" | "rpm" | "appimage" | "updater-manifest" | "updater-archive" | "signature" | "sbom" | "unknown";
export type DeliveryRole = "manual-only" | "mixed-manual-update" | "updater-only" | "supporting-file" | "unknown";
export type Channel = "stable" | "nightly";
export type SourceLabel = "download-home" | "github-readme" | "github-release" | "cmtraceopen-product" | "nightly-builds-page" | "project-docs" | "unknown";
export type AssetClassification = { platform: Platform; architecture: Architecture; edition: Edition; packageType: PackageType; deliveryRole: DeliveryRole };
export type ClassifiedReleaseAsset = AssetClassification & {
  id: number; name: string; size: number; contentType: string; browserDownloadUrl: string;
  releaseTag: string; channel: Channel; publishedAt: string;
};
export type NormalizedRelease = {
  tag: string; name: string; publishedAt: string; htmlUrl: string; assets: ClassifiedReleaseAsset[];
};
```

- [ ] **Step 2: Write the full current-filename fixture**

Include every asset returned for stable `v1.4.0` and the current `nightly` release, preserving `id`, `name`, `size`, `content_type`, `browser_download_url`, and expected classification. This must cover portable full/Lite x64/ARM64 EXEs, MSI, setup, DMG, AppImage, DEB, RPM, updater archives, `latest.json`, signatures, and both SBOMs.

- [ ] **Step 3: Write failing table-driven tests**

```ts
it.each(fixture.assets)("classifies $name", ({ name, expected }) => {
  expect(classifyAsset(name)).toEqual(expected);
});

it("leaves an unknown filename out of adoption totals", () => {
  expect(classifyAsset("mystery-download.bin")).toEqual({
    platform: "unknown", architecture: "unknown", edition: "unknown", packageType: "unknown", deliveryRole: "unknown",
  });
});

it.each(["download-home", "github-readme", "github-release", "cmtraceopen-product", "nightly-builds-page", "project-docs"])("accepts source %s", (source) => {
  expect(normalizeSource(source)).toBe(source);
});

it.each([null, "", "newsletter", "user-123", "cmtraceopen-product/extra"])("normalizes arbitrary source %s", (source) => {
  expect(normalizeSource(source)).toBe("unknown");
});
```

- [ ] **Step 4: Implement ordered, anchored rules**

The implementation order must be: manifest; SBOM; updater archive signature; updater archive; setup signature; setup; DMG; AppImage signature; AppImage; DEB signature; DEB; RPM signature; RPM; MSI; Lite portable EXE; full portable EXE; generic signature; unknown. Regexes must be anchored with `^` and `$` and accept both versioned stable and `Nightly_YYYYMMDD_RUN_SHA` stems.

Recommendation rank must return `0` only for full Windows x64 portable EXE, `10` for macOS ARM64 DMG, and `20` for Linux x64 AppImage; all other assets return `null` unless deliberately added later.

- [ ] **Step 5: Run tests and commit locally**

Run: `npm run test:worker -- tests/classify.test.ts`

Expected: every current filename and unknown/source edge case passes.

```bash
git add cmtraceopen-site/src/lib/releases/types.ts cmtraceopen-site/src/lib/releases/classify.ts cmtraceopen-site/tests/fixtures/release-assets.json cmtraceopen-site/tests/classify.test.ts
git commit -m "feat: classify CMTrace Open release assets"
```

### Task 3: Normalize and validate GitHub release data

**Files:**
- Create: `cmtraceopen-site/src/lib/releases/github.ts`
- Create: `cmtraceopen-site/tests/github.test.ts`

**Interfaces:**
- Produces: `getStableRelease(request: Request, fetcher?: typeof fetch): Promise<NormalizedRelease>`.
- Produces: `getVerifiedAsset(id: number, request: Request, fetcher?: typeof fetch): Promise<ClassifiedReleaseAsset>`.
- Produces: `isAllowedDownloadUrl(url: string): boolean`.

- [ ] **Step 1: Write failing normalization and security tests**

Cover:

```ts
expect(isAllowedDownloadUrl("https://github.com/adamgell/cmtraceopen/releases/download/v1.4.0/file.exe")).toBe(true);
expect(isAllowedDownloadUrl("http://github.com/adamgell/cmtraceopen/releases/download/v1.4.0/file.exe")).toBe(false);
expect(isAllowedDownloadUrl("https://evil.example/adamgell/cmtraceopen/releases/download/file.exe")).toBe(false);
expect(isAllowedDownloadUrl("https://github.com/other/repo/releases/download/v1/file.exe")).toBe(false);
expect(isAllowedDownloadUrl("https://github.com/adamgell/cmtraceopen/releases/tag/v1.4.0")).toBe(false);
```

Also assert the stable response excludes draft/prerelease data, preserves numeric IDs, derives channel `stable`, attaches classifications server-side, and marks exactly one recommended Windows package.

- [ ] **Step 2: Run tests and confirm missing-module failure**

Run: `npm run test:worker -- tests/github.test.ts`

Expected: FAIL because `github.ts` does not exist.

- [ ] **Step 3: Implement repository-scoped fetches and caching**

Use only:

```ts
const API = "https://api.github.com/repos/adamgell/cmtraceopen";
const HEADERS = {
  Accept: "application/vnd.github+json",
  "X-GitHub-Api-Version": "2022-11-28",
  "User-Agent": "cmtraceopen-download-worker",
};
```

Stable release lookup uses `/releases/latest`; asset lookup uses `/releases/assets/${id}`. Cache successful stable responses for 300 seconds and asset metadata for 3600 seconds. Do not cache 4xx/5xx. Treat a draft, prerelease, unknown classification, mismatched filename, nonnumeric ID, or disallowed target as an error.

- [ ] **Step 4: Run the focused tests**

Run: `npm run test:worker -- tests/github.test.ts`

Expected: PASS for normalization, caching, API failure, and every redirect-host rejection.

- [ ] **Step 5: Commit locally**

```bash
git add cmtraceopen-site/src/lib/releases/github.ts cmtraceopen-site/tests/github.test.ts
git commit -m "feat: validate GitHub release assets"
```

### Task 4: Build the matching stable-download center

**Files:**
- Create: `cmtraceopen-site/src/pages/_download/index.astro`
- Create: `cmtraceopen-site/src/components/download/PackageChooser.astro`
- Create: `cmtraceopen-site/src/scripts/download-center.ts`
- Create: `cmtraceopen-site/src/styles/download.css`
- Modify: `cmtraceopen-site/src/layouts/ProductLayout.astro`

**Interfaces:**
- Consumes: `GET /api/releases/stable` returning `NormalizedRelease`.
- Produces: links `/asset/{numericId}?source={SourceLabel}`; asset URLs never come from browser-provided metadata.
- Produces: Windows, macOS, Linux, and All Assets tabs with full portable x64 as Windows default recommendation.

- [ ] **Step 1: Write the failing browser contract**

In `tests/download.spec.ts`, mock `/api/releases/stable` with the stable fixture and assert:

```ts
await expect(page.getByRole("heading", { name: "Download CMTrace Open" })).toBeVisible();
await expect(page.getByText("Full portable application")).toBeVisible();
await expect(page.getByText("Recommended")).toBeVisible();
await expect(page.getByRole("link", { name: /Download x64/i })).toHaveAttribute("href", "/asset/475711960?source=cmtraceopen-product");
await expect(page.getByText("The binary never passes through our server.")).toBeVisible();
```

Add error-state assertions for a failed API request and a direct GitHub Releases fallback.

- [ ] **Step 2: Implement the static document and accessible chooser shell**

Use the approved order: stable release header; platform tabs; package stack; integrity panel; nightly panel; distribution trust band; shared footer. Tabs must be `<button role="tab">` with `aria-selected`, keyboard Left/Right support, and a visible tab panel.

- [ ] **Step 3: Implement client rendering with a source allowlist**

The client must:

```ts
const requestedSource = new URL(location.href).searchParams.get("source");
const source = normalizeSource(requestedSource ?? "download-home");
const hrefFor = (asset: ClassifiedReleaseAsset) => `/asset/${asset.id}?source=${encodeURIComponent(source)}`;
```

Render only `manual-only` and `mixed-manual-update` assets as normal package choices. Show updater/supporting files only in a separately labeled “Technical release files” group under All Assets, or link to the GitHub release record. Never label `latest.json` as a user download.

- [ ] **Step 4: Apply the shared Signal Room styling**

Reuse `tokens.css`; do not introduce a second color/token system. Preserve the approved cyan technical tabs, editorial package rows, release-integrity panel, nightly panel, and three-column trust band. At 850px the layout becomes one column; at 320px buttons fill available width without overflow.

- [ ] **Step 5: Run browser tests and commit locally**

Run: `npm run build && npx playwright test tests/download.spec.ts`

Expected: chooser, source propagation, keyboard tabs, error fallback, and narrow layout pass.

```bash
git add cmtraceopen-site/src/pages/_download/index.astro cmtraceopen-site/src/components/download/PackageChooser.astro cmtraceopen-site/src/scripts/download-center.ts cmtraceopen-site/src/styles/download.css cmtraceopen-site/src/layouts/ProductLayout.astro cmtraceopen-site/tests/download.spec.ts
git commit -m "feat: build branded stable download center"
```

### Task 5: Implement identifier-free aggregate events

**Files:**
- Create: `cmtraceopen-site/src/lib/releases/analytics.ts`
- Create: `cmtraceopen-site/analytics/schema.md`
- Create: `cmtraceopen-site/analytics/queries.sql`
- Create: `cmtraceopen-site/tests/analytics.test.ts`

**Interfaces:**
- Produces: `toAnalyticsDataPoint(asset: ClassifiedReleaseAsset, source: SourceLabel): AnalyticsEngineDataPoint`.
- Produces: `recordDownload(dataset: AnalyticsEngineDataset | undefined, asset, source): void` that never blocks a redirect.

- [ ] **Step 1: Write the privacy allowlist test**

Pass a request containing `CF-Connecting-IP`, `User-Agent`, `Cookie`, `Referer`, and arbitrary query parameters. Assert the output is exactly:

```ts
{
  indexes: [String(asset.id)],
  blobs: [String(asset.id), asset.releaseTag, asset.channel, asset.name, asset.platform, asset.architecture, asset.packageType, asset.deliveryRole, "github-readme"],
  doubles: [1],
}
```

Assert serialized output contains none of the header values, full referrer, or arbitrary query strings.

- [ ] **Step 2: Implement the single event-construction function**

Only `toAnalyticsDataPoint` may define column order. `recordDownload` catches missing-binding and write exceptions and returns without throwing. Do not log the request or exception object because it may include request metadata.

- [ ] **Step 3: Document ordered columns and retention**

`schema.md` must map `index1=asset_id`, `blob1=asset_id`, `blob2=release_tag`, `blob3=channel`, `blob4=filename`, `blob5=platform`, `blob6=architecture`, `blob7=package_type`, `blob8=delivery_role`, `blob9=source`, `double1=count`. State that Analytics Engine supplies `timestamp` automatically and retains events for three months; GitHub snapshot history is the long-lived aggregate source.

- [ ] **Step 4: Add sampling-aware aggregate SQL**

`queries.sql` must include:

```sql
SELECT blob9 AS source, SUM(_sample_interval * double1) AS selections
FROM cmtraceopen_download_events
WHERE timestamp >= NOW() - INTERVAL '30' DAY
GROUP BY source
ORDER BY selections DESC;

SELECT blob3 AS channel, blob5 AS platform, blob7 AS package_type, blob8 AS delivery_role,
       SUM(_sample_interval * double1) AS selections
FROM cmtraceopen_download_events
WHERE timestamp >= NOW() - INTERVAL '30' DAY
GROUP BY channel, platform, package_type, delivery_role
ORDER BY selections DESC;
```

- [ ] **Step 5: Run privacy tests and commit locally**

Run: `npm run test:worker -- tests/analytics.test.ts`

Expected: exact allowlist, missing binding, and throwing binding tests pass.

```bash
git add cmtraceopen-site/src/lib/releases/analytics.ts cmtraceopen-site/analytics cmtraceopen-site/tests/analytics.test.ts
git commit -m "feat: add private aggregate download events"
```

### Task 6: Add hostname dispatch, stable API, and safe redirect routes

**Files:**
- Create: `cmtraceopen-site/src/worker/index.ts`
- Create: `cmtraceopen-site/tests/worker.test.ts`
- Modify: `cmtraceopen-site/src/pages/index.astro`
- Modify: `cmtraceopen-site/src/pages/download.astro`
- Modify: `cmtraceopen-site/src/pages/nightly.astro`

**Interfaces:**
- `cmtraceopen.com/*` serves product assets; `/download/` returns 302 to `https://download.cmtraceopen.com/`; `/nightly/` returns 302 to the retained nightly page.
- `download.cmtraceopen.com/` internally serves `/_download/`; `GET /api/releases/stable` returns normalized JSON; `GET /asset/{id}` validates, counts, and redirects.
- `download.localhost` mirrors download-host behavior for local preview.

- [ ] **Step 1: Write host and route integration tests**

Use `SELF.fetch` or the exported handler with stub bindings to verify:

- Product `/` serves the flagship page.
- Download-host `/` serves the chooser, not the product hero.
- Product `/download/` and `/nightly/` return exact 302 locations.
- `/asset/not-a-number`, `/asset/0`, unknown IDs, cross-repository assets, and GitHub failures return 404 without calling analytics.
- A verified asset returns 302 to the exact `browser_download_url` and writes one event.
- A throwing analytics binding still returns the verified 302.
- Download-host product-only routes return a branded 404 rather than leaking internal `/_download/` paths.

- [ ] **Step 2: Implement deterministic host classification**

```ts
export type Surface = "product" | "download" | "unknown";
export function surfaceFor(hostname: string): Surface {
  const host = hostname.toLowerCase().split(":", 1)[0];
  if (["cmtraceopen.com", "www.cmtraceopen.com", "localhost", "product.localhost"].includes(host)) return "product";
  if (["download.cmtraceopen.com", "download.localhost"].includes(host)) return "download";
  return "unknown";
}
```

Unknown hosts return 421. Do not infer surface from request headers other than the URL hostname.

- [ ] **Step 3: Implement API and redirect routing**

Asset route parsing must match `^/asset/([1-9][0-9]*)/?$`. Resolve and classify server-side, normalize the source, call `recordDownload`, then return `Response.redirect(asset.browserDownloadUrl, 302)`. Do not accept target URL, filename, platform, or classification from query/body fields.

- [ ] **Step 4: Add security headers to every site response**

Apply:

```text
Content-Security-Policy: default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; connect-src 'self'; font-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'none'
Referrer-Policy: no-referrer
X-Content-Type-Options: nosniff
Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=(), usb=()
```

Do not add a reporting endpoint.

- [ ] **Step 5: Run Worker/browser tests and commit locally**

Run: `npm run test:worker && npx playwright test tests/download.spec.ts`

Expected: all host, security, privacy, redirect, and UI tests pass.

```bash
git add cmtraceopen-site/src/worker/index.ts cmtraceopen-site/tests/worker.test.ts cmtraceopen-site/src/pages/index.astro cmtraceopen-site/src/pages/download.astro cmtraceopen-site/src/pages/nightly.astro
git commit -m "feat: route verified branded downloads"
```

### Task 7: Scaffold the isolated GitHub snapshot tool

**Files:**
- Create: `tools/download-metrics/package.json`
- Create: `tools/download-metrics/tsconfig.json`
- Create: `tools/download-metrics/src/types.ts`
- Create: `tools/download-metrics/src/classify.ts`

**Interfaces:**
- Produces: isolated commands `npm test`, `npm run collect`, and `npm run check` without changing the Tauri application dependency graph.
- Produces: the same `classifyAsset`, `recommendationRank`, and contract version as the site.

- [ ] **Step 1: Create the isolated package**

```json
{
  "name": "cmtraceopen-download-metrics",
  "version": "0.1.0",
  "private": true,
  "type": "module",
  "engines": { "node": ">=22.12.0" },
  "scripts": {
    "check": "tsc --noEmit",
    "test": "vitest run",
    "collect": "tsx src/collect.ts"
  },
  "devDependencies": {
    "tsx": "4.23.1",
    "typescript": "6.0.3",
    "vitest": "4.1.10"
  }
}
```

- [ ] **Step 2: Define snapshot types**

```ts
export type AssetStatus = "current" | "replaced" | "deleted";
export type SnapshotAsset = {
  snapshotAt: string; releaseId: number; releaseTag: string; channel: "stable" | "nightly";
  publishedAt: string; prerelease: boolean; assetId: number; name: string; createdAt: string;
  updatedAt: string; size: number; contentType: string; downloadCount: number;
  platform: Platform; architecture: Architecture; edition: Edition; packageType: PackageType;
  deliveryRole: DeliveryRole; status: AssetStatus; delta: number | null;
};
export type Snapshot = { schemaVersion: 1; repository: "adamgell/cmtraceopen"; capturedAt: string; assets: SnapshotAsset[] };
export type GitHubAsset = { id: number; name: string; created_at: string; updated_at: string; size: number; content_type: string; download_count: number; browser_download_url: string };
export type GitHubRelease = { id: number; tag_name: string; name: string | null; published_at: string; prerelease: boolean; draft: boolean; assets: GitHubAsset[] };
export type RoleSummary = Record<DeliveryRole, { cumulative: number; delta: number }>;
```

- [ ] **Step 3: Copy the classifier exactly**

Copy `../static-adamgell/cmtraceopen-site/src/lib/releases/classify.ts` into `tools/download-metrics/src/classify.ts`, adjusting only the relative type import if required. Keep `CLASSIFICATION_CONTRACT = "2026-07-13.1"` identical.

- [ ] **Step 4: Install and type-check**

Run: `cd tools/download-metrics && npm install && npm run check`

Expected: lockfile is created and TypeScript passes.

- [ ] **Step 5: Commit locally**

```bash
git add -f tools/download-metrics/package.json tools/download-metrics/package-lock.json tools/download-metrics/tsconfig.json tools/download-metrics/src/types.ts tools/download-metrics/src/classify.ts
git commit -m "build: scaffold download metrics collector"
```

Do not stage `.claude/launch.json` and do not push.

### Task 8: Test the collector against the shared classification fixture

**Files:**
- Create: `tools/download-metrics/tests/fixtures/release-assets.json`
- Create: `tools/download-metrics/tests/classify.test.ts`
- Create: `tools/download-metrics/src/github.ts`
- Create: `tools/download-metrics/tests/github.test.ts`

**Interfaces:**
- Produces: `listReleases(fetcher, token?): Promise<GitHubRelease[]>` with pagination.
- Proves: site and collector classify the same current assets identically.

- [ ] **Step 1: Copy and compare the shared fixture**

Run:

```bash
cp ../static-adamgell/cmtraceopen-site/tests/fixtures/release-assets.json tools/download-metrics/tests/fixtures/release-assets.json
cmp ../static-adamgell/cmtraceopen-site/tests/fixtures/release-assets.json tools/download-metrics/tests/fixtures/release-assets.json
```

Expected: `cmp` exits 0.

- [ ] **Step 2: Add the same table-driven classification assertions**

Every fixture row must assert exact classification. Add a test asserting the contract string equals `2026-07-13.1`; unknown assets remain `unknown` and do not enter a headline role.

- [ ] **Step 3: Write pagination tests**

Mock pages 1, 2, and 3. Assert the client requests `per_page=100&page=N`, sends GitHub API version/accept headers, sends `Authorization: Bearer ...` only when a token is supplied, stops on an empty/short page, and throws a descriptive error on non-2xx.

- [ ] **Step 4: Implement the minimal GitHub client**

Use built-in `fetch`; do not add Octokit. The only endpoint is `https://api.github.com/repos/adamgell/cmtraceopen/releases?per_page=100&page=${page}`. Preserve all release and asset fields needed by `SnapshotAsset`.

- [ ] **Step 5: Run tests and commit locally**

Run: `npm test -- tests/classify.test.ts tests/github.test.ts`

Expected: fixture and pagination tests pass.

```bash
git add -f tools/download-metrics/tests/fixtures/release-assets.json tools/download-metrics/tests/classify.test.ts tools/download-metrics/src/github.ts tools/download-metrics/tests/github.test.ts
git commit -m "test: pin release metrics classification"
```

### Task 9: Implement delta, replacement, deletion, and reporting logic

**Files:**
- Create: `tools/download-metrics/src/reconcile.ts`
- Create: `tools/download-metrics/src/report.ts`
- Create: `tools/download-metrics/tests/reconcile.test.ts`
- Create: `tools/download-metrics/tests/report.test.ts`

**Interfaces:**
- Produces: `reconcileSnapshots(previous: Snapshot | null, currentAssets, capturedAt): Snapshot`.
- Produces: `buildSummary(snapshot): RoleSummary` and `toCsv(snapshot): string`.

- [ ] **Step 1: Write the reconciliation matrix**

Tests must cover:

- First observation has `delta: null`, not the cumulative count as a daily delta.
- Same asset ID count `10 -> 14` yields `delta: 4` and `status: current`.
- Same asset ID count `10 -> 9` throws `Negative download delta for asset {id}`.
- New nightly asset with the same logical key marks the old row `replaced` and the new row `current`.
- Missing asset without a logical replacement produces a `deleted` tombstone retaining its last observed count.
- Zero-count assets remain present.
- Unknown assets appear in diagnostics but contribute zero to headline totals.

Define logical key as `releaseTag + platform + architecture + edition + packageType + deliveryRole`; never use filename alone for replacement detection.

- [ ] **Step 2: Write reporting-semantics tests**

`buildSummary` must return separate totals/deltas for `manual-only`, `mixed-manual-update`, `updater-only`, `supporting-file`, and `unknown`. It must not expose a `users`, `installs`, `activeUsers`, `conversion`, or `unique` property.

- [ ] **Step 3: Implement reconciliation**

Index previous/current rows by numeric asset ID. Validate counts are finite nonnegative integers. Preserve deleted/replaced last observations as tombstones in the new snapshot so mutable nightly history remains interpretable.

- [ ] **Step 4: Implement deterministic JSON/CSV reports**

Sort rows by release tag, platform, architecture, package type, then asset ID. CSV must quote filenames and timestamps safely and use this stable header:

```text
snapshot_at,release_id,release_tag,channel,published_at,prerelease,asset_id,name,created_at,updated_at,size,content_type,download_count,delta,platform,architecture,edition,package_type,delivery_role,status
```

- [ ] **Step 5: Run tests and commit locally**

Run: `npm test -- tests/reconcile.test.ts tests/report.test.ts`

Expected: every delta/status/summary/CSV case passes.

```bash
git add -f tools/download-metrics/src/reconcile.ts tools/download-metrics/src/report.ts tools/download-metrics/tests/reconcile.test.ts tools/download-metrics/tests/report.test.ts
git commit -m "feat: derive release download metrics"
```

### Task 10: Add the collector CLI and dedicated-branch workflow

**Files:**
- Create: `tools/download-metrics/src/collect.ts`
- Create: `tools/download-metrics/tests/collect.test.ts`
- Create: `.github/workflows/download-metrics.yml`
- Create: `tools/download-metrics/README.md`

**Interfaces:**
- CLI: `npm run collect -- --output <directory> [--previous <latest.json>]`.
- Writes: `snapshots/YYYY/MM/<UTC timestamp>.json`, `reports/latest-assets.json`, `reports/latest-assets.csv`, and `reports/summary.json`.
- Workflow: schedule `17 0 * * *` and `workflow_dispatch`; eventual commits/push target only `download-metrics`.

- [ ] **Step 1: Write a deterministic CLI test**

Inject the clock as `2026-07-14T00:17:00.000Z` and a mocked two-release API. Assert exact output paths, JSON schema version, CSV header, summary role separation, and no files outside the provided temp output directory.

- [ ] **Step 2: Implement the CLI**

Reject an output directory resolving to the repository root or `.git`. Read `GITHUB_TOKEN` only for GitHub API authentication. Do not print the token or response headers. Exit nonzero on GitHub failure, invalid count, negative delta, or file-write failure; leave the last valid report untouched by writing temp files then renaming.

- [ ] **Step 3: Define the dormant-until-pushed workflow**

Use:

```yaml
name: Download metrics snapshot
on:
  schedule:
    - cron: "17 0 * * *"
  workflow_dispatch:
permissions:
  contents: write
concurrency:
  group: download-metrics
  cancel-in-progress: false
```

The job checks out `main`, runs the isolated tool tests, creates/opens a `metrics-worktree` for `origin/download-metrics`, runs the collector into that worktree, commits only `snapshots/` and `reports/`, and pushes `HEAD:download-metrics`. It must never execute `git push origin main`.

- [ ] **Step 4: Document local use and limitations**

State: GitHub counts are cumulative requests, not users/installations; the first snapshot is a baseline; direct GitHub and updater traffic remain included; negative deltas fail; the workflow has not been activated or pushed during local development.

- [ ] **Step 5: Run tests and commit locally**

Run:

```bash
cd tools/download-metrics
npm run check
npm test
npm run collect -- --output "$(mktemp -d)"
```

Expected: check/tests pass and a local snapshot/report set is generated; no Git commands run from the CLI.

```bash
git add -f tools/download-metrics/src/collect.ts tools/download-metrics/tests/collect.test.ts tools/download-metrics/README.md .github/workflows/download-metrics.yml
git commit -m "feat: add daily release download snapshots"
```

Do not dispatch or push the workflow.

### Task 11: Route project-controlled stable links without touching updater traffic

**Files:**
- Modify: `README.md`
- Modify: `.github/workflows/cmtrace-release.yml`
- Modify: `.github/workflows/codesign.yml`
- Modify: `.github/workflows/cmtrace-nightly-signed.yml`
- Create: `tools/download-metrics/tests/project-links.test.ts`

**Interfaces:**
- Human stable links use `https://download.cmtraceopen.com/?source=...`.
- Updater manifest endpoints and payload URLs remain `https://github.com/adamgell/cmtraceopen/releases/...`.

- [ ] **Step 1: Write a link-boundary test**

Create `tools/download-metrics/tests/project-links.test.ts` and assert:

```ts
expect(read("README.md")).toContain("https://download.cmtraceopen.com/?source=github-readme");
expect(read(".github/workflows/cmtrace-release.yml")).toContain("https://download.cmtraceopen.com/?source=github-release");
expect(read(".github/workflows/codesign.yml")).toContain("https://download.cmtraceopen.com/?source=github-release");
expect(read(".github/workflows/cmtrace-nightly-signed.yml")).toContain("https://adamgell.com/cmtraceopen/");
for (const updaterFile of ["src-tauri/tauri.conf.json", ".github/scripts/nightly-channel.mjs", ".github/workflows/codesign.yml"]) {
  expect(read(updaterFile)).not.toMatch(/download\.cmtraceopen\.com.*latest\.json/);
}
```

- [ ] **Step 2: Run the focused test and verify it fails**

Run: `cd tools/download-metrics && npm test -- tests/project-links.test.ts`

Expected: FAIL because human stable links still point directly to GitHub.

- [ ] **Step 3: Update human-facing copy only**

README primary download actions use `?source=github-readme`; stable release-body templates begin with `Stable downloads: https://download.cmtraceopen.com/?source=github-release`; nightly release notes begin with `Nightly build status and downloads: https://adamgell.com/cmtraceopen/`.

Do not modify `src-tauri/tauri.conf.json`, `.github/scripts/nightly-channel.mjs`, `latest.json` generation, or any updater payload URL.

- [ ] **Step 4: Run app/link verification**

Run:

```bash
cd tools/download-metrics && npm test -- tests/project-links.test.ts
cd ../.. && node --test .github/scripts/nightly-channel.test.mjs
npx tsc --noEmit
```

Expected: link boundary and nightly-channel tests pass; TypeScript reports zero errors.

- [ ] **Step 5: Commit locally**

```bash
git add README.md .github/workflows/cmtrace-release.yml .github/workflows/codesign.yml .github/workflows/cmtrace-nightly-signed.yml
git add -f tools/download-metrics/tests/project-links.test.ts
git commit -m "docs: favor branded stable downloads"
```

Do not edit the live release or push.

### Task 12: Attach the retained nightly page to the product family

**Repository:** `/Users/Adam.Gell/repo/static-adamgell`

**Files:**
- Modify: `public/cmtraceopen/index.html`
- Modify: `public/cmtraceopen/app.js`
- Modify: `public/cmtraceopen/styles.css`
- Create: `tests/cmtrace-nightly-links.test.mjs`

**Interfaces:**
- Header links: Product → `https://cmtraceopen.com/`; Stable Download → `https://download.cmtraceopen.com/?source=nightly-builds-page`.
- Human nightly asset links: `/asset/{numericId}?source=nightly-builds-page` on the branded host.
- `latest.json` and updater-only assets remain direct GitHub URLs and are not promoted as normal downloads.

- [ ] **Step 1: Write a failing DOM/source test**

Assert index contains both family links. Import/export `assetHref(asset)` from `app.js` and assert numeric asset IDs produce branded URLs, while `latest.json`, updater archives, signatures, and assets without numeric IDs keep their safe GitHub URL or are omitted from human groups according to existing visibility rules.

- [ ] **Step 2: Run the test and verify it fails**

Run: `node --test tests/cmtrace-nightly-links.test.mjs`

Expected: FAIL because the shared links/helper are absent.

- [ ] **Step 3: Implement human-only branded routing**

```js
export function assetHref(asset) {
  if (!Number.isSafeInteger(asset?.id) || asset.id <= 0) return asset?.browser_download_url ?? "";
  return `https://download.cmtraceopen.com/asset/${asset.id}?source=nightly-builds-page`;
}
```

Call this only for visible human-selected nightly assets. Keep GitHub API fetches, release records, updater metadata, and workflow links direct.

- [ ] **Step 4: Apply shared visual cues without changing page ownership**

Use the same ink/cyan/mono tokens and clear Product/Stable links, but retain “CMTrace Open Builds,” workflow status, nightly metadata, and its existing publication-focused information architecture.

- [ ] **Step 5: Verify and commit locally**

Run:

```bash
node --check public/cmtraceopen/app.js
node --test tests/cmtrace-nightly-links.test.mjs
npm run build
```

Expected: all pass and the broader Adam Gell site builds.

```bash
git add public/cmtraceopen/index.html public/cmtraceopen/app.js public/cmtraceopen/styles.css tests/cmtrace-nightly-links.test.mjs
git commit -m "feat: connect nightly builds to download center"
```

Do not push.

### Task 13: Run the full local-only acceptance gate

**Files:**
- Modify only if verification exposes a defect; keep each fix phase to five or fewer files.

**Interfaces:**
- Consumes: both repositories and every test suite above.
- Produces: locally verified product/download/snapshot behavior without external mutation.

- [ ] **Step 1: Prove classifier/fixture parity across repositories**

Run:

```bash
cmp /Users/Adam.Gell/repo/static-adamgell/cmtraceopen-site/src/lib/releases/classify.ts /Users/Adam.Gell/repo/cmtraceopen/tools/download-metrics/src/classify.ts
cmp /Users/Adam.Gell/repo/static-adamgell/cmtraceopen-site/tests/fixtures/release-assets.json /Users/Adam.Gell/repo/cmtraceopen/tools/download-metrics/tests/fixtures/release-assets.json
```

Expected: both exit 0. If type-import paths prevent byte identity, compare normalized copies and require identical contract version plus identical fixture results.

- [ ] **Step 2: Run both clean test suites**

Run:

```bash
cd /Users/Adam.Gell/repo/static-adamgell/cmtraceopen-site
rm -rf node_modules dist .astro
npm ci
npm run build
npm run test:worker
npm run test:e2e

cd /Users/Adam.Gell/repo/cmtraceopen/tools/download-metrics
rm -rf node_modules
npm ci
npm run check
npm test
```

Expected: every build, unit, Worker, content, accessibility, and browser test passes.

- [ ] **Step 3: Prove updater isolation**

Run:

```bash
cd /Users/Adam.Gell/repo/cmtraceopen
rg -n "download\.cmtraceopen\.com" src src-tauri .github/scripts
rg -n "github\.com/adamgell/cmtraceopen/releases/.+latest\.json|github\.com/adamgell/cmtraceopen/releases/.+-setup\.exe" src-tauri .github/scripts .github/workflows
```

Expected: first command returns no runtime/updater code references; second still finds direct GitHub updater manifest/payload references.

- [ ] **Step 4: Run a local Worker smoke test**

Start `npm run preview:worker` in `cmtraceopen-site`, then verify:

```bash
curl -I http://product.localhost:8787/
curl -I http://download.localhost:8787/
curl -i http://download.localhost:8787/api/releases/stable
curl -I "http://download.localhost:8787/asset/475711960?source=project-docs"
curl -i "http://download.localhost:8787/asset/not-a-number?source=user-123"
```

Expected: product and download surfaces differ correctly; stable JSON succeeds; verified asset returns the exact GitHub 302; invalid asset returns 404 and is not counted. Stop Wrangler afterward. Do not deploy.

- [ ] **Step 5: Audit local Git state and stop before publication**

Run in both repositories:

```bash
git status --short --branch
git log --oneline --decorate -15
git diff origin/main...HEAD --stat
```

Expected: local commits only. Do not run `git push`, `wrangler deploy`, `gh release edit`, `gh workflow run`, or any DNS/custom-domain command.

---

## Completion Gate

This plan is complete only when the local download center matches Signal Room, stable asset discovery and redirects are repository-verified, analytics payloads contain only the documented aggregate fields, analytics failure cannot block a valid download, daily snapshot logic preserves mutable-nightly history, project-controlled human links favor the branded host, updater traffic remains direct GitHub traffic, and neither repository nor any external service has been pushed or deployed.
