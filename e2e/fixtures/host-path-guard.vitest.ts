// Tests the e2e screenshot host-path guard. The .vitest.ts suffix is picked up
// by vitest (CI's `npm run test`) but not by Playwright's default
// *.spec/*.test matcher, so it does not run inside the e2e suite.
import os from "node:os";
import { describe, expect, it } from "vitest";

import {
  describeHostLeak,
  findHostLeaks,
  hostIdentifiers,
} from "./host-path-guard";

const IDS = [
  "/Users/Jane.Doe",
  "Jane.Doe",
  "JANES-MBP.corp.example",
  "JANES-MBP",
  "/work/cmtraceopen",
];

describe("host-path guard", () => {
  it.each(IDS)("flags the identifier %s", (id) => {
    expect(findHostLeaks(`Source: ${id}/x.log`, IDS)).toContain(id);
  });

  it("matches case-insensitively", () => {
    expect(findHostLeaks("c:\\users\\jane.doe\\desktop", IDS)).toContain(
      "Jane.Doe",
    );
    expect(findHostLeaks("janes-mbp", IDS)).toContain("JANES-MBP");
  });

  it("passes clean synthetic text", () => {
    expect(
      findHostLeaks("C:\\Fixture\\Logs\\ConfigMgr_AppEnforce_demo.log", IDS),
    ).toEqual([]);
    expect(describeHostLeak("Contoso VPN Client", "x", IDS)).toBeNull();
  });

  it("redacts every identifier in the failure message", () => {
    const message = describeHostLeak(
      "line one\n/Users/Jane.Doe/repo on JANES-MBP.corp.example\nline three",
      "log-viewer.png",
      IDS,
    );
    expect(message).not.toBeNull();
    expect(message).toMatch(/<host>/);
    expect(message).not.toMatch(/jane/i);
    expect(message).not.toMatch(/corp\.example/i);
  });

  it("includes the real home dir, host name and short host name", () => {
    const ids = hostIdentifiers().map((id) => id.toLowerCase());
    const host = os.hostname().toLowerCase();
    if (host.length > 2) {
      expect(ids).toContain(host);
      expect(ids).toContain(host.split(".")[0]);
    }
    expect(ids).toContain(os.homedir().toLowerCase());
  });
});
