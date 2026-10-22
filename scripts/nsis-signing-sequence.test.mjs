import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';

const workflow = readFileSync(new URL('../.github/workflows/codesign.yml', import.meta.url), 'utf8');
const steps = workflow.split(/^      - name: /m).slice(1);
function step(name) {
  const result = steps.find(block => block.startsWith(`${name}\n`));
  assert.ok(result, `missing ${name}`);
  return result;
}

test('NSIS payload signing occurs during bundling after credential-free compilation', () => {
  const compile = step('Compile full edition without bundling');
  const bundle = step('Bundle NSIS with signed application payload');
  assert.match(compile, /app:build:release .* --no-bundle/);
  assert.doesNotMatch(compile, /env:|AZURE_|SIGNING_/);
  assert.match(bundle, /signCommand/);
  assert.match(bundle, /\$powerShell = \(Get-Process -Id \$PID\)\.Path/);
  assert.match(bundle, /cmd = \$powerShell/);
  assert.match(bundle, /IsPathFullyQualified\(\$powerShell\)/);
  assert.match(bundle, /sign-tauri-windows\.ps1/);
  assert.match(bundle, /args = @\('-NoLogo', '-NoProfile', '-NonInteractive', '-File', \$hook, '%1'\)/);
  assert.match(bundle, /node scripts\/tauri\.mjs bundle .* --bundles nsis --config \$configPath/);
  assert.doesNotMatch(bundle, /tauri\.mjs build|app:build|npm ci|Install-Module/);
  assert.match(bundle, /if \(\$LASTEXITCODE -ne 0\).*throw/);
  const ordered = [compile, bundle, step('Save full edition binary'),
    step('Build lite edition (standalone EXE)'), step('Sign release EXEs'),
    step('Verify NSIS bundled application signature'),
    step('Generate updater signature for NSIS installer')].map(block => steps.indexOf(block));
  assert.deepEqual(ordered, [...ordered].sort((a, b) => a - b));
});

test('bundler hook uses the existing action module version and credential names', () => {
  const download = step('Download pinned Artifact Signing package for bundler hook');
  const digest = '3221344b8c627915d3870f23e80816f31a5d8c2bae1d7c0cdd6c9652f6c4e089';
  assert.match(download, /https:\/\/www\.powershellgallery\.com\/api\/v2\/package\/ArtifactSigning\/0\.1\.8/);
  assert.ok(download.includes(digest));
  assert.match(download, /Get-FileHash -LiteralPath \$package -Algorithm SHA256/);
  assert.doesNotMatch(download, /secrets\.|Import-Module|Install-Module/);
  const hook = readFileSync(new URL('sign-tauri-windows.ps1', import.meta.url), 'utf8');
  assert.ok(hook.includes(digest));
  assert.match(hook, /Get-FileHash -InputStream \$stream -Algorithm SHA256/);
  assert.match(hook, /Import-Module -Name \$manifest -RequiredVersion 0\.1\.8 -Force -PassThru/);
  assert.match(hook, /& \$module\.ExportedCommands\['Invoke-ArtifactSigning'\]/);
  assert.doesNotMatch(hook, /Import-Module ArtifactSigning|Install-Module/);
  assert.ok(hook.indexOf('Get-FileHash') < hook.indexOf('ExtractToDirectory'));
  assert.ok(hook.indexOf('ExtractToDirectory') < hook.indexOf('Import-Module'));
  const bundle = step('Bundle NSIS with signed application payload');
  assert.ok(steps.indexOf(download) < steps.indexOf(bundle));
  for (const name of ['AZURE_TENANT_ID', 'AZURE_CLIENT_ID', 'AZURE_CLIENT_SECRET',
    'SIGNING_ENDPOINT', 'SIGNING_ACCOUNT_NAME', 'SIGNING_PROFILE_NAME']) {
    assert.ok(bundle.includes(`secrets.${name}`));
    assert.ok(step('Sign release EXEs').includes(`secrets.${name}`));
  }
});

test('sanitized hook receipts are retained even when bundling fails', () => {
  const diagnostics = step('Upload sanitized bundler hook diagnostics');
  assert.match(diagnostics, /if: always\(\)/);
  assert.ok(diagnostics.includes('path: ${{ runner.temp }}/cmtrace-signing-hooks/*.json'));
  assert.match(diagnostics, /if-no-files-found: ignore/);
  assert.doesNotMatch(diagnostics, /secrets\.|\*\.log|include-hidden-files/);
});
