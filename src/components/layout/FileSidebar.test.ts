import { describe, expect, it } from "vitest";
import {
  formatBytes,
  formatCount,
  formatModified,
  isFolderLikeSource,
} from "./FileSidebar";

describe("formatCount", () => {
  it("uses the singular only for exactly one", () => {
    expect(formatCount(1, "file")).toBe("1 file");
    expect(formatCount(0, "file")).toBe("0 files");
    expect(formatCount(2, "file")).toBe("2 files");
  });

  it("accepts an explicit plural", () => {
    expect(formatCount(2, "entry", "entries")).toBe("2 entries");
    expect(formatCount(1, "entry", "entries")).toBe("1 entry");
  });
});

describe("formatBytes", () => {
  it("reports an unknown size rather than zero", () => {
    expect(formatBytes(null)).toBe("Size unknown");
  });

  it("keeps sub-kilobyte sizes in bytes", () => {
    expect(formatBytes(0)).toBe("0 B");
    expect(formatBytes(1023)).toBe("1023 B");
  });

  it("crosses to KB at exactly 1024", () => {
    expect(formatBytes(1024)).toBe("1.0 KB");
  });

  it("drops the decimal past ten units", () => {
    expect(formatBytes(10 * 1024)).toBe("10 KB");
    expect(formatBytes(1024 * 1024)).toBe("1.0 MB");
    expect(formatBytes(1024 * 1024 * 1024)).toBe("1.0 GB");
  });

  it("stops at TB rather than inventing a unit", () => {
    // The unit list ends at TB, so a larger value is scaled into TB rather
    // than overflowing the array.
    const result = formatBytes(2048 * 1024 ** 4);
    expect(result.endsWith("TB")).toBe(true);
    expect(result).not.toContain("undefined");
  });
});

describe("formatModified", () => {
  it("reports an absent time as unavailable", () => {
    expect(formatModified(null)).toBe("Modified time unavailable");
  });

  it("formats an epoch-0 timestamp instead of treating it as absent", () => {
    // `!unixMs` also rejects 0. The backend yields Some(0) for a file whose mtime
    // is 1970-01-01, so this must not read as "unavailable".
    const result = formatModified(0);
    expect(result).not.toBe("Modified time unavailable");
  });
});

describe("isFolderLikeSource", () => {
  it("recognises a folder source and a known source pointing at a folder", () => {
    expect(isFolderLikeSource({ kind: "folder" } as never)).toBe(true);
    expect(
      isFolderLikeSource({ kind: "known", pathKind: "folder" } as never),
    ).toBe(true);
  });

  it("rejects a file source, a known file source, and no source", () => {
    expect(isFolderLikeSource({ kind: "file" } as never)).toBe(false);
    expect(
      isFolderLikeSource({ kind: "known", pathKind: "file" } as never),
    ).toBe(false);
    expect(isFolderLikeSource(null)).toBe(false);
  });
});
