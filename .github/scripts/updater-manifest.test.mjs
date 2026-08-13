import assert from "node:assert/strict";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";

import {
  UPDATER_TARGETS,
  buildUpdaterManifest,
  readSignatures,
} from "./updater-manifest.mjs";

const VERSION = "1.5.3";
const TAG_NAME = "v1.5.3";
const REPOSITORY = "adamgell/cmtraceopen";
const PUB_DATE = "2026-08-14T00:00:00.000Z";

function signaturesFor(keys) {
  const signatures = new Map();
  for (const target of UPDATER_TARGETS) {
    if (!keys.includes(target.key)) continue;
    signatures.set(`${target.artifact(VERSION)}.sig`, `sig-for-${target.key}`);
  }
  return signatures;
}

function build(overrides = {}) {
  return buildUpdaterManifest({
    version: VERSION,
    tagName: TAG_NAME,
    repository: REPOSITORY,
    signatures: new Map(),
    pubDate: PUB_DATE,
    ...overrides,
  });
}

const ALL_KEYS = UPDATER_TARGETS.map((target) => target.key);
const WINDOWS_KEYS = ALL_KEYS.filter((key) => key.startsWith("windows-"));
const UNIX_KEYS = ALL_KEYS.filter((key) => !key.startsWith("windows-"));

test("resolves every updater target when all signatures are present", () => {
  const { manifest, missing } = build({ signatures: signaturesFor(ALL_KEYS) });

  assert.deepEqual(missing, []);
  assert.deepEqual(Object.keys(manifest.platforms).sort(), [...ALL_KEYS].sort());
  assert.equal(manifest.version, TAG_NAME);
  assert.equal(manifest.notes, `CMTrace Open ${TAG_NAME}`);
});

test("points each target at its own artifact under the release tag", () => {
  const { manifest } = build({ signatures: signaturesFor(ALL_KEYS) });

  assert.equal(
    manifest.platforms["windows-aarch64"].url,
    `https://github.com/${REPOSITORY}/releases/download/${TAG_NAME}/CMTrace-Open_${VERSION}_arm64-setup.exe`,
  );
  assert.equal(
    manifest.platforms["linux-x86_64-rpm"].url,
    `https://github.com/${REPOSITORY}/releases/download/${TAG_NAME}/CMTrace.Open-${VERSION}-1.x86_64.rpm`,
  );
});

test("aliased targets share one artifact", () => {
  const { manifest } = build({ signatures: signaturesFor(ALL_KEYS) });

  assert.equal(
    manifest.platforms["darwin-aarch64"].url,
    manifest.platforms["darwin-aarch64-app"].url,
  );
  assert.equal(
    manifest.platforms["linux-x86_64"].url,
    manifest.platforms["linux-x86_64-appimage"].url,
  );
});

test("reports the targets it could not resolve instead of throwing", () => {
  const { manifest, missing } = build({ signatures: signaturesFor(WINDOWS_KEYS) });

  assert.deepEqual(missing.sort(), [...UNIX_KEYS].sort());
  assert.deepEqual(Object.keys(manifest.platforms).sort(), [...WINDOWS_KEYS].sort());
});

// The property that makes concurrent publishers safe: the manifest is a
// function of the release's assets, not of which workflow computed it.
test("two publishers seeing the same assets produce identical manifests", () => {
  const first = build({ signatures: signaturesFor(ALL_KEYS) });
  const second = build({ signatures: signaturesFor(ALL_KEYS) });

  assert.deepEqual(first.manifest, second.manifest);
});

// The property that makes an out-of-order publisher safe: a run that cannot see
// the other platform's artifacts yet must not delete its entries. This is the
// exact regression that shipped v1.5.2 without windows-aarch64 and then, on the
// repair run, without any Linux key at all.
test("carries published entries forward when their artifacts are not visible", () => {
  const published = {
    version: TAG_NAME,
    notes: `CMTrace Open ${TAG_NAME}`,
    pub_date: "2026-08-13T12:00:00Z",
    platforms: Object.fromEntries(
      UNIX_KEYS.map((key) => [
        key,
        { signature: "already-published", url: "https://example.invalid/asset", version: TAG_NAME },
      ]),
    ),
  };

  const { manifest, missing } = build({
    signatures: signaturesFor(WINDOWS_KEYS),
    publishedManifest: published,
  });

  assert.deepEqual(missing, []);
  assert.deepEqual(Object.keys(manifest.platforms).sort(), [...ALL_KEYS].sort());
  assert.equal(manifest.platforms["linux-x86_64-deb"].signature, "already-published");
  assert.equal(manifest.platforms["windows-x86_64"].signature, "sig-for-windows-x86_64");
});

test("a freshly built entry replaces the published one for the same target", () => {
  const published = {
    pub_date: "2026-08-13T12:00:00Z",
    platforms: {
      "windows-x86_64": { signature: "stale", url: "https://example.invalid/old", version: "v1.5.2" },
    },
  };

  const { manifest } = build({
    signatures: signaturesFor(["windows-x86_64"]),
    publishedManifest: published,
  });

  assert.equal(manifest.platforms["windows-x86_64"].signature, "sig-for-windows-x86_64");
  assert.equal(manifest.platforms["windows-x86_64"].version, TAG_NAME);
});

test("keeps the original publication date across republishes", () => {
  const { manifest } = build({
    signatures: signaturesFor(ALL_KEYS),
    publishedManifest: { pub_date: "2026-08-13T12:00:00Z", platforms: {} },
  });

  assert.equal(manifest.pub_date, "2026-08-13T12:00:00Z");
});

test("stamps a publication date on the first publish", () => {
  const { manifest } = build({ signatures: signaturesFor(ALL_KEYS) });

  assert.equal(manifest.pub_date, PUB_DATE);
});

test("strips the line endings Windows runners leave on signature files", async () => {
  const directory = mkdtempSync(path.join(tmpdir(), "updater-manifest-"));

  try {
    writeFileSync(path.join(directory, "windows.exe.sig"), "dGF1cmktc2ln\r\n");
    writeFileSync(path.join(directory, "unix.AppImage.sig"), "dGF1cmktc2ln\n");
    writeFileSync(path.join(directory, "not-a-signature.exe"), "ignored");

    const signatures = await readSignatures(directory, [
      "windows.exe.sig",
      "unix.AppImage.sig",
      "not-a-signature.exe",
    ]);

    assert.equal(signatures.get("windows.exe.sig"), "dGF1cmktc2ln");
    assert.equal(signatures.get("unix.AppImage.sig"), "dGF1cmktc2ln");
    assert.equal(signatures.has("not-a-signature.exe"), false);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

// Guards the contract the Tauri updater actually reads. A renamed or dropped
// key is silent at runtime: affected users simply stop being offered updates.
test("target list matches the keys the updater expects", () => {
  assert.deepEqual(
    [...ALL_KEYS].sort(),
    [
      "darwin-aarch64",
      "darwin-aarch64-app",
      "linux-x86_64",
      "linux-x86_64-appimage",
      "linux-x86_64-deb",
      "linux-x86_64-rpm",
      "windows-aarch64",
      "windows-x86_64",
    ],
  );
});
