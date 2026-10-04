import assert from 'node:assert/strict';
import { existsSync, readFileSync, readdirSync } from 'node:fs';
import path from 'node:path';
import test from 'node:test';

const root = path.resolve(import.meta.dirname, '..');
const read = (name) => readFileSync(path.join(root, name), 'utf8');
const parser = 'crates/cmtraceopen-parser/src/';

function sources(directory) {
  return readdirSync(path.join(root, directory), { withFileTypes: true })
    .flatMap((entry) => {
      const name = `${directory}/${entry.name}`;
      return entry.isDirectory() ? sources(name) : /\.(rs|ts|tsx)$/.test(name) ? [name] : [];
    });
}

test('IME and ESP have only their canonical workload module owners', () => {
  assert.ok(existsSync(path.join(root, parser, 'intune/apps/windows/ime/mod.rs')));
  assert.ok(existsSync(path.join(root, parser, 'intune/enrollment/windows/esp/mod.rs')));
  assert.doesNotMatch(read(`${parser}lib.rs`), /^pub mod esp;/m);
  for (const name of ['download_stats', 'event_tracker', 'guid_registry', 'ime_parser', 'models', 'policy_parser', 'timeline']) {
    assert.ok(!existsSync(path.join(root, parser, `intune/${name}.rs`)), name);
    assert.doesNotMatch(read(`${parser}intune/mod.rs`), new RegExp(`pub mod ${name};`));
  }
});

test('CCM framing and shared identity helpers are below workload ownership', () => {
  for (const name of ['parser/ccm/logical.rs', 'intune/common/identity.rs']) {
    assert.doesNotMatch(read(`${parser}${name}`), /(?:crate::)?intune::apps|super::(?:\w+::)*ime\b/);
  }
  assert.doesNotMatch(read(`${parser}parser/ccm.rs`), /intune::(?:ime_parser|apps)/);
  assert.match(read(`${parser}intune/enrollment/windows/esp/reducer.rs`), /intune::common::identity/);
});

test('assigned ESP compatibility commands, batch and discovery are absent from production', () => {
  const obsolete = /\b(?:ParsedEspEventBatch|parse_esp_evtx_file_bounded|restart_esp_as_administrator|restartEspAsAdministrator|EspRelaunchReason|EspRelaunchResult|EspRelaunchError|resolve_legacy_artifacts|legacy_allowed_path|MAX_LEGACY_BUNDLE_DEPTH|MAX_LEGACY_BUNDLE_ENTRIES)\b/;
  for (const file of [...sources('src-tauri/src'), ...sources('src')].filter((name) => !/\.test\.tsx?$/.test(name))) {
    assert.ok(!obsolete.test(read(file)), `${file} retains an assigned obsolete symbol`);
  }
  assert.match(read('src-tauri/src/lib.rs'), /commands::elevation::restart_as_administrator/);
  assert.match(read('src/lib/commands.ts'), /export async function restartAsAdministrator/);
});
