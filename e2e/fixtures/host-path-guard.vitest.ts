// Tests the e2e screenshot host-path guard. The .vitest.ts suffix is picked up
// by vitest (CI's `npm run test`) but not by Playwright's default
// *.spec/*.test matcher, so it does not run inside the e2e suite.
import os from "node:os";
import { afterEach, describe, expect, it, vi } from "vitest";

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

  describe("hostIdentifiers length rules", () => {
    afterEach(() => {
      vi.restoreAllMocks();
    });

    const lower = () => hostIdentifiers().map((id) => id.toLowerCase());

    it("always includes the home dir and working directory", () => {
      expect(lower()).toContain(os.homedir().toLowerCase());
      expect(lower()).toContain(process.cwd().toLowerCase());
    });

    it("includes the user name only when longer than 2 characters", () => {
      const user = os.userInfo().username.toLowerCase();
      expect(lower().includes(user)).toBe(user.length > 2);
    });

    it.each([
      ["my-host.corp.example", true, true],
      ["workstation", true, true],
      ["ci.example.com", true, false],
      ["ab.example.com", true, false],
      ["ab", false, false],
    ])(
      "host name %s: full included=%s, short label included=%s",
      (host, fullIncluded, shortIncluded) => {
        vi.spyOn(os, "hostname").mockReturnValue(host);
        const ids = lower();
        expect(ids.includes(host)).toBe(fullIncluded);
        const short = host.split(".")[0];
        // A short label that equals the whole host name is the same entry.
        if (short !== host) {
          expect(ids.includes(short)).toBe(shortIncluded);
        } else {
          expect(ids.includes(short)).toBe(fullIncluded);
        }
      },
    );
  });
});
