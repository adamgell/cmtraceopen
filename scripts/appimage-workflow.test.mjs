import assert from "node:assert/strict";
import { readFileSync, writeFileSync, mkdirSync, mkdtempSync, rmSync, chmodSync, existsSync, readdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import test from "node:test";

const workflow = (name) => readFileSync(new URL(`../.github/workflows/${name}.yml`, import.meta.url), "utf8");

test("Linux CI refreshes the preinstalled FreeType provider before archive inspection", () => {
  const build = workflow("cmtrace-ci").split("\n  build:\n")[1];
  const install = build.split("- name: Install Linux dependencies\n")[1].split("\n      - name:")[0];
  assert.match(install, /sudo apt-get update/);
  const packages = install.split("sudo apt-get install -y")[1];
  assert.match(packages, /\blibfreetype6\b/);
  assert.doesNotMatch(install, /apt-get (?:upgrade|dist-upgrade)|allow-unauthenticated|trusted=yes/);
  assert.ok(build.indexOf("- name: Install Linux dependencies") < build.indexOf("- name: Build Tauri app"));
});

test("only application package producers select the Ubuntu 22.04 baseline", () => {
  for (const name of ["cmtrace-ci", "cmtrace-release"]) {
    assert.match(workflow(name), /- os: ubuntu-22\.04\n\s+target: x86_64-unknown-linux-gnu/);
  }
  assert.match(workflow("cmtrace-ci"), /check:\n\s+name: Check & Test \(Rust\)\n\s+runs-on: ubuntu-latest/);
});

test("compiled application caches cannot restore a different Ubuntu baseline", () => {
  const build = workflow("cmtrace-ci").split("\n  build:\n")[1];
  for (const line of build.split("\n").filter((line) => /(?:key|restore-keys):/.test(line) && /cargo/.test(line))) {
    assert.match(line, /\$\{\{ matrix\.os \}\}-\$\{\{ matrix\.target \}\}-cargo-appimage-v1-/);
  }
});

test("both producers require the archive guard inside the pinned action build command", () => {
  for (const name of ["cmtrace-ci", "cmtrace-release"]) {
    const text = workflow(name);
    const action = text.split("uses: tauri-apps/tauri-action@")[1].split("\n      - name:")[0];
    assert.ok(action.includes("CMTRACE_APPIMAGE_VERIFY_ROOT: ${{ runner.os == 'Linux' && 'src-tauri/target/x86_64-unknown-linux-gnu/release/bundle' || '' }}"), name);
    if (name === "cmtrace-ci") assert.ok(action.includes("SOURCE_COMMIT: ${{ github.event.pull_request.head.sha || github.sha }}"), name);
    // A release dispatch checks out the tag; github.sha is the workflow ref.
    // Its source identity must come from the checked-out commit.
    else assert.ok(!action.includes("SOURCE_COMMIT:"), name);
    assert.ok(text.includes("squashfs-tools python3-venv python3-apt"), name);
    assert.ok(text.includes("--system-site-packages .appimage-abi-venv"), name);
    assert.ok(text.includes("--require-hashes --only-binary=:all: -r scripts/appimage-abi-requirements.txt"), name);
    assert.ok(text.indexOf("run: node scripts/ci-bundle-outputs.mjs clean") < text.indexOf("uses: tauri-apps/tauri-action@"), name);
    assert.ok(text.includes("provenance/appimage-abi.json"), name);
  }
});

test("CI runs the archive policy and wrapper regressions", () => {
  const text = workflow("cmtrace-ci");
  assert.ok(text.includes("scripts/appimage-workflow.test.mjs"));
  assert.ok(text.includes(".appimage-abi-venv/bin/python -B -m unittest discover -s scripts -p appimage_abi_test.py"));
});

test("release evidence retains the uploaded AppImage and report under their bundle directories", () => {
  const steps = workflow("cmtrace-release").split("\n      - name: ");
  const buildIndex = steps.findIndex((step) => step.startsWith("Build and create release\n"));
  assert.ok(buildIndex >= 0);
  const build = steps[buildIndex];
  const evidence = steps[buildIndex + 1];
  // The pinned action awaits buildProject(), then uploadReleaseAssets(). Keep
  // this upload immediately after it, with no rebuild, signing or copy step.
  assert.match(build, /uses: tauri-apps\/tauri-action@1deb371b0cd8bd54025b384f1cd735e725c4060f /);
  assert.ok(build.includes("TAURI_SIGNING_PRIVATE_KEY: ${{ secrets.TAURI_SIGNING_PRIVATE_KEY }}"));
  assert.ok(build.includes("args: --target ${{ matrix.target }}"));
  assert.ok(evidence.startsWith("Upload AppImage inspection evidence\n"));
  assert.match(evidence, /if: runner\.os == 'Linux'\n/);
  assert.match(evidence, /uses: actions\/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a /);
  assert.ok(evidence.includes("name: appimage-abi-${{ matrix.label }}"));
  assert.match(evidence, /if-no-files-found: error/);
  assert.doesNotMatch(evidence, /continue-on-error|always\(\)|\n\s+run:/);
  const paths = evidence.match(/          path: \|\n((?:            .+\n)+)/)?.[1]
    .trim().split("\n").map((path) => path.trim());
  const root = "src-tauri/target/${{ matrix.target }}/release/bundle/";
  // upload-artifact@043fb46's multi-path LCA is bundle/, so the downloaded
  // artifact has appimage/<name>.AppImage and provenance/appimage-abi.json.
  assert.deepEqual(paths, [root + "appimage/*.AppImage", root + "provenance/appimage-abi.json"]);
});

test('release builds locally and gates package upload on macOS trust and retained evidence', () => {
  const text = workflow('cmtrace-release');
  const build = text.split('      - name: Build and create release\n')[1].split('\n      - name:')[0];
  assert.doesNotMatch(build, /tagName:|releaseId:|releaseName:|releaseBody:|releaseDraft:/);
  const uploadAt = text.indexOf('- name: Upload verified release bundles');
  assert.ok(uploadAt > text.indexOf('- name: Verify macOS release trust and payload identity'));
  assert.ok(uploadAt > text.indexOf('- name: Retain macOS trust verification receipts'));
  assert.ok(uploadAt > text.indexOf('- name: Attest release artifacts'));
  const upload = text.slice(uploadAt).split('\n      - name:')[0];
  assert.doesNotMatch(upload, /always\(\)|continue-on-error/);
  for (const name of ['aarch64.dmg','aarch64.app.tar.gz','amd64.AppImage','amd64.deb','1.x86_64.rpm',
    'macos-trust.json','provenance/appimage-abi.json']) assert.ok(upload.includes(name), name);
  assert.match(upload,/cmp -s/);
});

function stageFixture(os, mode = 'complete') {
  const root = mkdtempSync(join(tmpdir(), 'verified-upload-'));
  try {
    const put = (name, value='verified bytes') => {
      const path=join(root,name); mkdirSync(join(path,'..'),{recursive:true}); writeFileSync(path,value);
    };
    const files = os === 'macOS' ? ['dmg/CMTrace Open_1.6.3_aarch64.dmg', 'macos/CMTrace Open.app.tar.gz']
      : ['appimage/CMTrace Open_1.6.3_amd64.AppImage','deb/cmtrace-open_1.6.3_amd64.deb','rpm/cmtrace-open-1.6.3-1.x86_64.rpm'];
    for (const file of files) {
      put('bundle/'+file);
      if (!file.endsWith('.dmg') && mode !== 'missing-signature') put('bundle/'+file+'.sig','signature bytes');
    }
    if (mode === 'ambiguous') put('bundle/'+files[0].replace(/[^/]+$/,'second'+(os==='macOS'?'.dmg':'.AppImage')));
    if (mode !== 'missing-receipt') {
      const receipt={status:mode==='failed-receipt'?'FAIL':'PASS', version:'1.6.3', sourceCommit:'a'.repeat(40),
        artifacts:files.map(f=>({path:'bundle/'+f,sha256:createHash('sha256').update('verified bytes').digest('hex')}))};
      put(os==='macOS'?'release-verification/macos/macos-trust.json':'bundle/provenance/appimage-abi.json',JSON.stringify(receipt));
    }
    if(mode==='changed-payload') put('bundle/'+files[0],'changed after verification');
    put('bin/gh', '#!/bin/sh\nif [ "$2" = view ]; then printf "v1.6.3\\n"; else printf "uploaded\\n" > upload-called; fi\n');
    chmodSync(join(root,'bin/gh'),0o755);
    put('bin/git', '#!/bin/sh\nprintf "'+ 'a'.repeat(40) +'\\n"\n');
    chmodSync(join(root,'bin/git'),0o755);
    // Only the remote upload is substituted; real copies and comparisons run.
    const text=workflow('cmtrace-release').split('      - name: Upload verified release bundles\n')[1];
    const shell=text.split('        run: |\n')[1].split('\n      - name:')[0].split('\n').map(l=>l.slice(10)).join('\n');
    const result=spawnSync('bash',['-c',shell],{cwd:root,encoding:'utf8',timeout:10000,
      env:{...process.env,PATH:`${join(root,'bin')}:${process.env.PATH}`,RUNNER_OS:os,BUNDLE_ROOT:'bundle',VERSION:'1.6.3',TAG_NAME:'v1.6.3'}});
    return {result, root};
  } catch(error) { rmSync(root,{recursive:true,force:true}); throw error; }
}
for (const os of ['macOS','Linux']) {
  test(`${os} uploads canonical bundle/signature names without changing source bytes`, () => {
    const {root,result}=stageFixture(os);
    try {
      assert.equal(result.status,0,result.stderr);
      assert.ok(existsSync(join(root,'upload-called')));
      const staged=readdirSync(join(root,'release-assets'));
      assert.equal(staged.length,os==='macOS'?4:7);
      const packageName=os==='macOS'?'CMTrace.Open_1.6.3_aarch64.app.tar.gz':'CMTrace.Open_1.6.3_amd64.AppImage';
      assert.equal(readFileSync(join(root,'release-assets',packageName),'utf8'),'verified bytes');
      assert.equal(readFileSync(join(root,'release-assets',packageName+'.sig'),'utf8'),'signature bytes');
    } finally { rmSync(root,{recursive:true,force:true}); }
  });
  for (const mode of ['missing-signature','ambiguous','missing-receipt',...(os==='macOS'?['changed-payload','failed-receipt']:[])]) {
    test(`${os} ${mode} prevents remote package upload`, () => {
      const {root,result}=stageFixture(os,mode);
      try { assert.notEqual(result.status,0); assert.equal(existsSync(join(root,'upload-called')),false); }
      finally { rmSync(root,{recursive:true,force:true}); }
    });
  }
}

function draftPreflightFixture(mode) {
  const text=workflow('cmtrace-release');
  const marker='      - name: Wait for exact draft release\n';
  assert.ok(text.includes(marker),'Draft existence must be checked before Unix setup/build');
  const at=text.indexOf(marker);
  assert.ok(at > text.indexOf('      - name: Resolve release tag'));
  assert.ok(at < text.indexOf('      - uses: actions/checkout@'));
  assert.ok(at < text.indexOf('      - name: Import Apple Developer Certificate'));
  assert.ok(at < text.indexOf('      - name: Notarize and staple final macOS DMG'));
  const block=text.split(marker)[1].split('\n      - uses:')[0];
  assert.match(block,/timeout-minutes: 5/);
  assert.match(block,/GH_REPO: \$\{\{ github.repository \}\}/);
  assert.doesNotMatch(block,/gh release create|gh release edit|gh workflow run/);
  const root=mkdtempSync(join(tmpdir(),'draft-preflight-'));
  try {
    mkdirSync(join(root,'bin'));
    writeFileSync(join(root,'bin/gh'),`#!${process.execPath}
import fs from 'node:fs';
const count=fs.existsSync('calls')?Number(fs.readFileSync('calls','utf8'))+1:1;
fs.writeFileSync('calls',String(count));
const mode=process.env.FIXTURE_MODE;
if(mode==='api-error') process.exit(1);
const release={id:42,tag_name:'v1.6.3',draft:mode!=='published',prerelease:mode==='prerelease'};
const matches=mode==='absent'||(mode==='eventual'&&count<3)?[]:mode==='duplicate'?[release,release]:[release];
console.log(JSON.stringify([[{id:1,tag_name:'v1.0.0'}],matches]));
`,{mode:0o755});
    writeFileSync(join(root,'bin/sleep'),'#!/bin/sh\nprintf "%s\\n" "$1" >> sleeps\n',{mode:0o755});
    const shell=block.split('        run: |\n')[1].split('\n').map(l=>l.slice(10)).join('\n');
    const result=spawnSync('bash',['-c',shell],{cwd:root,encoding:'utf8',timeout:10000,
      env:{...process.env,PATH:`${join(root,'bin')}:${process.env.PATH}`,RUNNER_TEMP:root,
        GH_REPO:'adamgell/cmtraceopen',TAG_NAME:'v1.6.3',FIXTURE_MODE:mode}});
    const calls=Number(readFileSync(join(root,'calls'),'utf8'));
    const sleeps=existsSync(join(root,'sleeps'))?readFileSync(join(root,'sleeps'),'utf8').trim().split('\n').map(Number):[];
    return {result,calls,sleeps};
  } finally { rmSync(root,{recursive:true,force:true}); }
}
test('Unix preflight waits for Windows-created exact draft before any checkout or signing',()=>{
  const {result,calls,sleeps}=draftPreflightFixture('eventual');
  assert.equal(result.status,0,result.stderr); assert.equal(calls,3); assert.deepEqual(sleeps,[10,10]);
});
test('absent draft exhausts its fixed bound without creating a release',()=>{
  const {result,calls,sleeps}=draftPreflightFixture('absent');
  assert.notEqual(result.status,0); assert.equal(calls,24); assert.equal(sleeps.length,23);
  assert.ok(sleeps.every(seconds=>seconds===10));
  // Windows currently waits twelve ten-second intervals before creating a
  // missing draft. Unix must not time out before its sole creator can act.
  const windows=workflow('codesign').split('- name: Ensure GitHub release exists')[1].split('\n  windows-signed-release:')[0];
  assert.match(windows,/\$attempt -le 12/); assert.match(windows,/Start-Sleep -Seconds 10/);
  assert.ok(sleeps.reduce((sum,s)=>sum+s,0)>12*10);
});
for(const mode of ['published','prerelease','duplicate','api-error']) {
  test(`Unix preflight fails immediately for ${mode}`,()=>{
    const {result,calls,sleeps}=draftPreflightFixture(mode);
    assert.notEqual(result.status,0); assert.equal(calls,1); assert.deepEqual(sleeps,[]);
  });
}
