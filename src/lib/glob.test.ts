import { describe, expect, it } from "vitest";
import { matchesAnyPattern } from "./glob";

describe("matchesAnyPattern", () => {
  describe("empty patterns", () => {
    it("returns true for any filename when patterns array is empty", () => {
      expect(matchesAnyPattern("anything.log", [])).toBe(true);
      expect(matchesAnyPattern("", [])).toBe(true);
    });
  });

  describe("wildcard-all pattern", () => {
    it("matches everything with '*'", () => {
      expect(matchesAnyPattern("foo.txt", ["*"])).toBe(true);
      expect(matchesAnyPattern("", ["*"])).toBe(true);
    });
  });

  describe("exact match (no wildcard)", () => {
    it("matches exact name case-insensitively", () => {
      expect(matchesAnyPattern("setupact.log", ["setupact.log"])).toBe(true);
      expect(matchesAnyPattern("SetupAct.log", ["setupact.log"])).toBe(true);
      expect(matchesAnyPattern("setupact.log", ["SETUPACT.LOG"])).toBe(true);
    });

    it("rejects non-matching exact names", () => {
      expect(matchesAnyPattern("other.log", ["setupact.log"])).toBe(false);
    });
  });

  describe("suffix wildcard (*.ext)", () => {
    it("matches files by extension", () => {
      expect(matchesAnyPattern("trace.log", ["*.log"])).toBe(true);
      expect(matchesAnyPattern("data.LOG", ["*.log"])).toBe(true);
    });

    it("rejects files with different extension", () => {
      expect(matchesAnyPattern("trace.txt", ["*.log"])).toBe(false);
    });
  });

  describe("prefix wildcard (prefix*)", () => {
    it("matches files starting with prefix", () => {
      expect(matchesAnyPattern("IntuneManagementExtension.log", ["Intune*"])).toBe(true);
    });

    it("rejects files not starting with prefix", () => {
      expect(matchesAnyPattern("Other.log", ["Intune*"])).toBe(false);
    });
  });

  describe("prefix and suffix (prefix*.ext)", () => {
    it("matches files matching both prefix and extension", () => {
      expect(matchesAnyPattern("IntuneManagementExtension.log", ["Intune*.log"])).toBe(true);
    });

    it("rejects files matching prefix but not extension", () => {
      expect(matchesAnyPattern("IntuneManagementExtension.txt", ["Intune*.log"])).toBe(false);
    });

    it("rejects files matching extension but not prefix", () => {
      expect(matchesAnyPattern("Other.log", ["Intune*.log"])).toBe(false);
    });
  });

  describe("middle wildcard (*middle*)", () => {
    it("matches when middle substring is present", () => {
      expect(matchesAnyPattern("my-setup-trace.log", ["*setup*"])).toBe(true);
    });

    it("rejects when middle substring is absent", () => {
      expect(matchesAnyPattern("my-trace.log", ["*setup*"])).toBe(false);
    });
  });

  describe("multiple patterns (OR logic)", () => {
    it("matches if any pattern matches", () => {
      expect(matchesAnyPattern("trace.log", ["*.txt", "*.log"])).toBe(true);
      expect(matchesAnyPattern("notes.txt", ["*.txt", "*.log"])).toBe(true);
    });

    it("rejects if no pattern matches", () => {
      expect(matchesAnyPattern("data.csv", ["*.txt", "*.log"])).toBe(false);
    });
  });

  describe("edge cases", () => {
    it("handles overlapping prefix and suffix segments", () => {
      // Pattern "ab*ab" on name "ab" should fail because the prefix and suffix
      // segments cannot both fit in a 2-character string.
      expect(matchesAnyPattern("ab", ["ab*ab"])).toBe(false);
      expect(matchesAnyPattern("abab", ["ab*ab"])).toBe(true);
      expect(matchesAnyPattern("abXab", ["ab*ab"])).toBe(true);
    });

    it("handles pattern with consecutive wildcards", () => {
      expect(matchesAnyPattern("foo.log", ["**foo**"])).toBe(true);
    });

    it("handles single character filenames", () => {
      expect(matchesAnyPattern("a", ["a"])).toBe(true);
      expect(matchesAnyPattern("a", ["b"])).toBe(false);
    });
  });
});
