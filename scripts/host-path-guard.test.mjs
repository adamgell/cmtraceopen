import assert from "node:assert/strict";
import os from "node:os";
import test from "node:test";

import {
  describeHostLeak,
  findHostLeaks,
  hostIdentifiers,
} from "../e2e/fixtures/host-path-guard.ts";

const IDS = [
  "/Users/Jane.Doe",
  "Jane.Doe",
  "JANES-MBP.corp.example",
  "JANES-MBP",
  "/work/cmtraceopen",
];

test("flags each identifier kind", () => {
  for (const id of IDS) {
    assert.deepEqual(findHostLeaks(`Source: ${id}/x.log`, IDS).includes(id), true, id);
  }
});

test("matching is case-insensitive", () => {
  assert.ok(findHostLeaks("c:\\users\\jane.doe\\desktop", IDS).includes("Jane.Doe"));
  assert.ok(findHostLeaks("janes-mbp", IDS).includes("JANES-MBP"));
});

test("clean synthetic text passes", () => {
  assert.deepEqual(findHostLeaks("C:\\Fixture\\Logs\\ConfigMgr_AppEnforce_demo.log", IDS), []);
  assert.equal(describeHostLeak("Contoso VPN Client", "x", IDS), null);
});

test("failure message redacts every identifier", () => {
  const message = describeHostLeak(
    "line one\n/Users/Jane.Doe/repo on JANES-MBP.corp.example\nline three",
    "log-viewer.png",
    IDS,
  );
  assert.ok(message);
  assert.match(message, /<host>/);
  assert.doesNotMatch(message, /jane/i);
  assert.doesNotMatch(message, /corp\.example/i);
});

test("real identifiers include the host name and its short label", () => {
  const ids = hostIdentifiers().map((id) => id.toLowerCase());
  const host = os.hostname().toLowerCase();
  if (host.length > 2) {
    assert.ok(ids.includes(host));
    assert.ok(ids.includes(host.split(".")[0]));
  }
  assert.ok(ids.includes(os.homedir().toLowerCase()));
});
