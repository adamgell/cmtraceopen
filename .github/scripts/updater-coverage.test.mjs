import assert from 'node:assert/strict';
import { readFileSync, writeFileSync, mkdirSync, mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import test from 'node:test';
import { UPDATER_TARGETS, buildUpdaterManifest, missingUpdaterAssets, assertCompleteUpdaterManifest } from './updater-manifest.mjs';
const version = '1.6.3', tagName = 'v1.6.3', repository = 'adamgell/cmtraceopen';
const names = [...new Set(UPDATER_TARGETS.map(t => t.artifact(version)))];
const assets = names.flatMap(name => [{name, state: "uploaded"}, {name: `${name}.sig`, state: "uploaded"}]);
const signatures = new Map(names.map(name => [`${name}.sig`, `signature-${name}`]));
const build = (sig = signatures, publishedManifest = null) => buildUpdaterManifest({version, tagName, repository, signatures: sig, publishedManifest, pubDate: '2026-10-10T00:00:00Z'}).manifest;

test('all six artifacts and six signature assets are required', () => {
  assert.deepEqual(missingUpdaterAssets({version, tagName, assets}), []);
  for (const asset of assets) assert.deepEqual(missingUpdaterAssets({version, tagName, assets: assets.filter(a => a !== asset)}), [asset.name]);
});
test('unfinished artifact and signature uploads remain missing', () => {
  for (const asset of assets) {
    for (const state of ['open', undefined]) {
      const pending = assets.map(candidate => candidate === asset ? {...candidate, state} : candidate);
      assert.deepEqual(missingUpdaterAssets({version, tagName, assets: pending}), [asset.name]);
    }
  }
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

// Execute the actual composite shell, substituting only GitHub and the wait.
// Reverting draft discovery, identity validation or bounded retry breaks these.
function publishFixture(mode) {
  const root = mkdtempSync(join(tmpdir(), 'updater-publish-'));
  try {
    mkdirSync(join(root, 'bin')); mkdirSync(join(root, '.github/scripts'), {recursive: true});
    writeFileSync(join(root, '.github/scripts/updater-manifest.mjs'), readFileSync(new URL('./updater-manifest.mjs', import.meta.url)));
    writeFileSync(join(root, 'fixture.json'), JSON.stringify({id: 42, tag_name: tagName, draft: true, prerelease: false,
      created_at: '2026-10-10T00:00:00Z', assets}));
    writeFileSync(join(root, 'bin/gh'), `#!${process.execPath}
import fs from 'node:fs';
const args=process.argv.slice(2), r=JSON.parse(fs.readFileSync('fixture.json')), mode=process.env.FIXTURE_MODE;
fs.appendFileSync('calls.jsonl', JSON.stringify(args)+'\\n');
if(args[0]==='api') {
  if(args.includes('--paginate') && args.includes('--slurp')) {
    if(mode==='api-error') process.exit(1);
    console.log(JSON.stringify([[{id: 1, tag_name:'v0.0.1'}], mode==='duplicate'?[r,r]:mode==='absent'?[]:[r]]));
  } else if(args.some(a=>a.endsWith('/releases/42'))) {
    if(mode==='wrong-tag') r.tag_name='v9.9.9';
    if(mode==='wrong-id') r.id=43;
    if(mode==='prerelease') r.prerelease=true;
    if(mode==='invalid-date') r.created_at=null;
    if(mode==='missing') r.assets=[];
    console.log(JSON.stringify(r));
  } else process.exit(1); // Published-tag lookup intentionally cannot see drafts.
} else if(args[1]==='download') {
  const dir=args[args.indexOf('--dir')+1];
  if(args.includes('latest.json')) fs.copyFileSync('uploaded.json',dir+'/latest.json');
  else for(const a of r.assets.filter(a=>a.name.endsWith('.sig'))) fs.writeFileSync(dir+'/'+a.name,'signature-'+a.name);
} else if(args[1]==='upload') fs.copyFileSync('latest.json','uploaded.json');
else process.exit(1);
`, {mode: 0o755});
    for (const [name, body] of [['sleep', 'exit 0'], ['seq', "printf '1\\n40\\n'"]]) {
      writeFileSync(join(root, 'bin', name), `#!/bin/sh\n${body}\n`, {mode: 0o755});
    }
    const action = readFileSync(new URL('../actions/publish-updater-manifest/action.yml', import.meta.url), 'utf8');
    const shell = action.split('      run: |\n')[1].split('\n').map(line=>line.slice(8)).join('\n');
    const result = spawnSync('bash', ['-c', shell], {cwd: root, encoding: 'utf8', timeout: 10000,
      env: {...process.env, PATH: `${join(root,'bin')}:${process.env.PATH}`, FIXTURE_MODE: mode,
        GH_REPO: repository, GITHUB_REPOSITORY: repository, TAG_NAME: tagName, VERSION: version,
        GITHUB_STEP_SUMMARY: join(root,'summary.md')}});
    const calls = readFileSync(join(root,'calls.jsonl'),'utf8').trim().split('\n').map(JSON.parse);
    const uploaded=calls.some(c=>c[1]==='upload');
    return {result, calls, uploaded, manifest:uploaded?JSON.parse(readFileSync(join(root,'uploaded.json'),'utf8')):null};
  } finally { rmSync(root,{recursive:true,force:true}); }
}
test('publisher finds a draft on later release pages and uses its fixed ID snapshot', () => {
  const {result,calls,uploaded,manifest}=publishFixture('draft');
  assert.equal(result.status,0,result.stderr); assert.ok(uploaded);
  assert.equal(manifest.pub_date,'2026-10-10T00:00:00Z');
  assert.equal(Object.keys(manifest.platforms).length,8);
  assert.ok(calls.some(c=>c.includes('--paginate') && c.includes('--slurp')));
  assert.equal(calls.filter(c=>c.some(a=>a.endsWith('/releases/42'))).length,1);
});
for (const mode of ['duplicate','absent','wrong-tag','wrong-id','prerelease','invalid-date','api-error']) {
  test(`publisher fails immediately without upload for ${mode}`, () => {
    const {result,calls,uploaded}=publishFixture(mode);
    assert.notEqual(result.status,0); assert.equal(uploaded,false);
    assert.ok(calls.filter(c=>c.some(a=>a.endsWith('/releases/42'))).length <= 1);
  });
}
test('only incomplete assets retry and exhaustion cannot upload a partial manifest', () => {
  const {result,calls,uploaded}=publishFixture('missing');
  assert.notEqual(result.status,0); assert.equal(uploaded,false);
  assert.equal(calls.filter(c=>c.some(a=>a.endsWith('/releases/42'))).length,2);
});
