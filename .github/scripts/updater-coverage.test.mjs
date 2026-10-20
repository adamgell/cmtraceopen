import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import { UPDATER_TARGETS, buildUpdaterManifest, missingUpdaterAssets, assertCompleteUpdaterManifest } from './updater-manifest.mjs';
const version = '1.6.3', tagName = 'v1.6.3', repository = 'adamgell/cmtraceopen';
const names = [...new Set(UPDATER_TARGETS.map(t => t.artifact(version)))];
const assets = names.flatMap(name => [{name}, {name: `${name}.sig`}]);
const signatures = new Map(names.map(name => [`${name}.sig`, `signature-${name}`]));
const build = (sig = signatures, publishedManifest = null) => buildUpdaterManifest({version, tagName, repository, signatures: sig, publishedManifest, pubDate: '2026-10-10T00:00:00Z'}).manifest;

test('all six artifacts and six signature assets are required', () => {
  assert.deepEqual(missingUpdaterAssets({version, tagName, assets}), []);
  for (const asset of assets) assert.deepEqual(missingUpdaterAssets({version, tagName, assets: assets.filter(a => a !== asset)}), [asset.name]);
});
test('old manifest cannot supply absent current signatures', () => {
  assert.throws(() => assertCompleteUpdaterManifest({manifest: build(new Map(), build()), version, tagName, repository, signatures: new Map(), assets}), /signature|coverage/i);
});
test('complete current manifest passes and every missing key fails', () => {
  assertCompleteUpdaterManifest({manifest: build(), version, tagName, repository, signatures, assets});
  for (const target of UPDATER_TARGETS) {
    const manifest = build(); delete manifest.platforms[target.key];
    assert.throws(() => assertCompleteUpdaterManifest({manifest, version, tagName, repository, signatures, assets}), /coverage/i);
  }
});
test('stale URLs, versions, altered signatures and extra keys fail', () => {
  for (const change of [p => p.url += '?old', p => p.version = 'v1.6.2', p => p.signature = 'different']) {
    const manifest = build(); change(manifest.platforms['windows-x86_64']);
    assert.throws(() => assertCompleteUpdaterManifest({manifest, version, tagName, repository, signatures, assets}), /entry/i);
  }
  const manifest = build(); manifest.platforms.unsupported = {};
  assert.throws(() => assertCompleteUpdaterManifest({manifest, version, tagName, repository, signatures, assets}), /coverage/i);
});
test('invalid release identity and duplicate assets fail', () => {
  assert.throws(() => missingUpdaterAssets({version, tagName: 'v1.6.2', assets}), /version/i);
  assert.throws(() => missingUpdaterAssets({version, tagName, assets: [...assets, assets[0]]}), /duplicate/i);
});
test('empty signatures cannot pass complete coverage', () => {
  const empty = new Map(signatures); empty.set(`${names[0]}.sig`, '');
  assert.throws(() => assertCompleteUpdaterManifest({manifest: build(empty), version, tagName, repository, signatures: empty, assets}), /signature/i);
});
test('publisher waits before any upload and compares complete content', () => {
  const action = readFileSync(new URL('../actions/publish-updater-manifest/action.yml', import.meta.url), 'utf8');
  assert.ok(action.indexOf('--check-assets') < action.indexOf('gh release upload'));
  assert.match(action, /\.platforms == \$actual\[0\]\.platforms/);
});

test('numeric stable tags accepted by release workflow retain their exact URLs', () => {
  assert.deepEqual(missingUpdaterAssets({version, tagName: version, assets}), []);
});
