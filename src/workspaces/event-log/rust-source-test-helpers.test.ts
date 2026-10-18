/**
 * The shared Rust-source helpers read a checkout made with CRLF line endings (Git for Windows with
 * `core.autocrlf=true`, which `.gitattributes` does not override for `*.rs`) exactly as one made
 * with LF. Each case builds the CRLF copy from the LF text, so the test passes on either checkout.
 */
import { describe, expect, it } from "vitest";
import analysisSessionRaw from "../../../src-tauri/src/event_log/analysis_session.rs?raw";
import timelineRaw from "../../../src-tauri/src/event_log/timeline.rs?raw";
import parserTimelineRaw from "../../../crates/cmtraceopen-parser/src/unified_timeline/mod.rs?raw";
import {
  constantValue,
  itemText,
  normalizeLineEndings,
  squash,
  squashCode,
} from "./rust-source-test-helpers";

const toCrlf = (text: string) => normalizeLineEndings(text).replace(/\n/g, "\r\n");

const FIRST = [
  "fn first(x: u32) -> u32 {",
  "    // a } in a comment",
  '    let s = "a } in a string \\" with a quote";',
  "    if x > s.len() as u32 {",
  "        x",
  "    } else {",
  "        0",
  "    }",
  "}",
].join("\n");
const SNIPPET = ["// header { not a brace", "const LIMIT: usize = 4 * 64;", "", FIRST, "", "fn second() {}", ""].join("\n");

describe("normalizeLineEndings", () => {
  it("reads CRLF as LF and leaves LF alone", () => {
    expect(normalizeLineEndings("a\r\nb\r\n")).toBe("a\nb\n");
    expect(normalizeLineEndings("a\nb\n")).toBe("a\nb\n");
  });
});

describe("itemText", () => {
  it("extracts the item through its closing brace, ignoring braces in strings and line comments", () => {
    expect(itemText(SNIPPET, "fn first(")).toBe(FIRST);
    expect(itemText(SNIPPET, "fn second(")).toBe("fn second() {}");
  });

  it("extracts the same item from a CRLF copy as from the LF copy", () => {
    const crlf = toCrlf(SNIPPET);
    expect(crlf).toContain("\r\n}\r\n");
    expect(crlf).not.toContain("\n}\n");
    expect(itemText(crlf, "fn first(")).toBe(FIRST);
    expect(itemText(crlf, "fn second(")).toBe("fn second() {}");
  });

  it("extracts the same item from a CRLF copy of each real source a pin reads", () => {
    const items: readonly (readonly [string, string, string])[] = [
      ["unified_timeline/mod.rs", parserTimelineRaw, "fn is_collector_bundle_id("],
      ["unified_timeline/mod.rs", parserTimelineRaw, "pub fn bundle_from_source("],
      ["event_log/timeline.rs", timelineRaw, "fn origin_of("],
      ["event_log/timeline.rs", timelineRaw, "fn compact_timeline_text("],
      ["event_log/analysis_session.rs", analysisSessionRaw, "fn sanitize_malformed_timeline_record("],
    ];
    for (const [file, raw, signature] of items) {
      const lf = itemText(normalizeLineEndings(raw), signature);
      expect(lf.length, `${file} ${signature}`).toBeGreaterThan(40);
      expect(itemText(toCrlf(raw), signature), `${file} ${signature}`).toBe(lf);
    }
  });

  it("says so when the signature is missing or not unique, or the body never closes", () => {
    expect(() => itemText(SNIPPET, "fn third(")).toThrow(/no longer has/);
    expect(() => itemText(`${FIRST}\n${FIRST}`, "fn first(")).toThrow(/no longer unique/);
    expect(() => itemText("fn open() {\n    let a = 1;\n", "fn open(")).toThrow(/no closing brace/);
    expect(() => itemText(toCrlf("fn open() {\n    let a = 1;\n"), "fn open(")).toThrow(/no closing brace/);
  });
});

describe("squash and squashCode", () => {
  it("squash drops whitespace of either line ending", () => {
    expect(squash("a b\r\n\tc")).toBe("abc");
    expect(squash(toCrlf(FIRST))).toBe(squash(FIRST));
  });

  it("squashCode also drops line comments, so a reworded comment and a CRLF copy compare equal", () => {
    const reworded = FIRST.replace("// a } in a comment", "// another remark, longer than the first");
    expect(squashCode(reworded)).toBe(squashCode(FIRST));
    expect(squashCode(toCrlf(FIRST))).toBe(squashCode(FIRST));
    expect(squashCode(FIRST)).not.toBe(squashCode(FIRST.replace("x > s.len()", "x >= s.len()")));
  });
});

describe("constantValue", () => {
  it("reads a product of integer literals from either line ending", () => {
    expect(constantValue(SNIPPET, "LIMIT")).toBe(256);
    expect(constantValue(toCrlf(SNIPPET), "LIMIT")).toBe(256);
    expect(() => constantValue(SNIPPET, "MISSING")).toThrow(/no longer has/);
  });
});
