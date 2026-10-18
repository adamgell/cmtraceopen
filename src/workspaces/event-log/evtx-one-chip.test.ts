/**
 * One kind chip (#843, spec 8.13). The EVT / LOG chip is drawn by EvtxKindChip and by nothing else
 * in the Event Logs workspace.
 *
 * The retired timeline chip was a bare `<span>` that wrote `{fromEvent ? "EVT" : "LOG"}` as its text
 * and picked its colors from the same condition. It carried no `data-chip` attribute, so a guard on
 * that attribute alone would never have seen it. This guard looks for what such a chip must contain
 * instead: the kind written as text or compared against, the chip's two names, and the attribute.
 *
 * The allow-list is the files that may hold the literal, and each says why. Passing the kind to the
 * chip (`chip={...}`) is not drawing it, so that attribute's value is set aside before the scan.
 */
import { describe, expect, it } from "vitest";

/** The files that may write EVT or LOG, and why. Keep it small: a new entry is a decision. */
const ALLOWED_TO_WRITE_THE_KIND: Record<string, string> = {
  "EvtxKindChip.tsx": "draws the chip and types its prop",
  "evtx-unplaced.ts": "produces the kind of an unplaced row",
  "evtx-detail-context-model.ts": "produces the kind of a Details context row",
};

/** The only file that may name the chip or give it a `data-chip` attribute. */
const CHIP_FILE = "EvtxKindChip.tsx";

/**
 * `source` with its comments blanked (newlines kept) and its string contents left as written, so a
 * comment cannot hide a literal and a literal cannot hide behind a `//` inside a string.
 */
function withoutComments(source: string): string {
  let out = "";
  let i = 0;
  while (i < source.length) {
    const char = source[i]!;
    const next = source[i + 1];
    if (char === "/" && next === "/") {
      while (i < source.length && source[i] !== "\n") i += 1;
    } else if (char === "/" && next === "*") {
      const end = source.indexOf("*/", i + 2);
      const stop = end === -1 ? source.length : end + 2;
      out += source.slice(i, stop).replace(/[^\n]/g, " ");
      i = stop;
    } else if (char === '"' || char === "'" || char === "`") {
      let j = i + 1;
      while (j < source.length && source[j] !== char) j += source[j] === "\\" ? 2 : 1;
      out += source.slice(i, j + 1);
      i = j + 1;
    } else {
      out += char;
      i += 1;
    }
  }
  return out;
}

/** The kinds of drawing a source may hold, as short descriptions; empty for a clean source. */
export function chipDrawingIn(source: string): string[] {
  const code = withoutComments(source)
    // Handing the kind to the chip is the one allowed use of the literal outside the files above.
    .replace(/\bchip=\{[^{}]*\}/g, "chip={}")
    .replace(/\bchip=(["'])(?:EVT|LOG)\1/g, "chip={}");
  const found: string[] = [];
  if (/>\s*(?:EVT|LOG)\s*</.test(code)) found.push("EVT or LOG as the text of a JSX node");
  if (/(?:\?|:|===?|!==?|\bcase)\s*(["'`])(?:EVT|LOG)\1/.test(code)) found.push("a condition on EVT or LOG");
  if (/(["'`])(?:EVT|LOG)\1/.test(code)) found.push("an EVT or LOG literal");
  return found;
}

/** What names or marks a chip: the two accessible names and the attribute the tests select by. */
export function chipMarkersIn(source: string): string[] {
  const code = withoutComments(source);
  const found: string[] = [];
  if (/(["'`])(?:Windows event|Text log line)\1/.test(code)) found.push("the chip's accessible name");
  if (/\bdata-chip\b/.test(code)) found.push("the data-chip attribute");
  return found;
}

/** Every source of the workspace that is not a test, a test helper or a fixture. */
const sources = Object.fromEntries(
  Object.entries(
    import.meta.glob("./**/*.{ts,tsx}", { query: "?raw", import: "default", eager: true }) as Record<string, string>,
  )
    .filter(([path]) => !/\.test\.tsx?$|-test-helpers\.|-test-fixtures\.|\/__fixtures__\//.test(path))
    .map(([path, source]) => [path.replace(/^\.\//, ""), source]),
);

describe("the scan sees what it must", () => {
  it("reads the workspace, and the chip and the allow-listed producers are among what it reads", () => {
    expect(Object.keys(sources).length).toBeGreaterThan(50);
    for (const file of [CHIP_FILE, ...Object.keys(ALLOWED_TO_WRITE_THE_KIND)]) expect(Object.keys(sources)).toContain(file);
  });

  it("flags the retired timeline chip, which had no data-chip attribute", () => {
    const retired = `
      <span
        style={{ width: "40px", flexShrink: 0, textAlign: "center", fontWeight: 700,
          backgroundColor: fromEvent ? tokens.colorBrandBackground2 : tokens.colorNeutralBackground4 }}
        title={fromEvent ? "Windows event" : "Text log line"}
      >
        {fromEvent ? "EVT" : "LOG"}
      </span>`;
    expect(retired).not.toContain("data-chip");
    expect(chipDrawingIn(retired)).toEqual(["a condition on EVT or LOG", "an EVT or LOG literal"]);
    expect(chipMarkersIn(retired)).toEqual(["the chip's accessible name"]);
  });

  it.each([
    ["the kind as JSX text", "<span>EVT</span>", ["EVT or LOG as the text of a JSX node"]],
    ["the kind as spaced JSX text", "<b>\n  LOG\n</b>", ["EVT or LOG as the text of a JSX node"]],
    ["a comparison", 'const isEvt = kind === "EVT";', ["a condition on EVT or LOG", "an EVT or LOG literal"]],
    ["a branch", 'const c = ok ? "LOG" : other;', ["a condition on EVT or LOG", "an EVT or LOG literal"]],
    ["a switch case", 'switch (k) { case "EVT": return 1; }', ["a condition on EVT or LOG", "an EVT or LOG literal"]],
    ["a bare literal", 'const KIND = "EVT";', ["an EVT or LOG literal"]],
    ["a single-quoted literal", "const KIND = 'LOG';", ["an EVT or LOG literal"]],
    ["a literal after a // inside a string", 'const url = "http://x"; const KIND = "EVT";', ["an EVT or LOG literal"]],
    ["a literal after a comment on the line before", '// a note\nconst KIND = "LOG";', ["an EVT or LOG literal"]],
    [
      "a literal drawn after a chip attribute, on the same line",
      '<EvtxKindChip chip={kind} /><b>EVT</b>',
      ["EVT or LOG as the text of a JSX node"],
    ],
    [
      "a literal drawn after a chip attribute, further down",
      '<EvtxKindChip chip={kind} />\n<p>{ok ? "LOG" : null}</p>',
      ["a condition on EVT or LOG", "an EVT or LOG literal"],
    ],
  ])("flags %s", (_name, source, expected) => {
    expect(chipDrawingIn(source)).toEqual(expected);
  });

  it.each([
    ["the kind handed to the chip", '<EvtxKindChip chip={fromEvent ? "EVT" : "LOG"} />'],
    ["a literal kind handed to the chip", '<EvtxKindChip chip="EVT" />'],
    ["the kind handed on two lines", '<EvtxKindChip\n  chip={isEvent(o)\n    ? "EVT" : "LOG"}\n/>'],
    ["a line comment", "// the EVT chip\nconst a = 1;"],
    ["a doc comment", '/**\n * EVT / LOG: "EVT" is a Windows event.\n */\nconst a = 1;'],
    ["a longer string that has the word in it", 'const label = isEvt ? "UNPLACED EVT" : "UNPLACED LOG";'],
    ["other words", 'const a = "EVTX"; const b = "LOGS"; const c = "log";'],
    ["a generic type", "const a: Array<EVT> = [];"],
  ])("does not flag %s", (_name, source) => {
    expect(chipDrawingIn(source)).toEqual([]);
  });

  it("flags the chip's names and attribute outside the chip, and not in a comment or in longer copy", () => {
    expect(chipMarkersIn('<span data-chip="EVT" />')).toEqual(["the data-chip attribute"]);
    expect(chipMarkersIn('const t = "Text log line";')).toEqual(["the chip's accessible name"]);
    expect(chipMarkersIn("// data-chip is read by the tests")).toEqual([]);
    expect(chipMarkersIn('const t = "Windows event log (EVTX)";')).toEqual([]);
  });
});

describe("EVT and LOG chips are drawn by one component", () => {
  const files = Object.keys(sources).sort();

  it("writes no EVT or LOG in any source outside the allow-list", () => {
    const drawing = files
      .filter((file) => !(file in ALLOWED_TO_WRITE_THE_KIND))
      .flatMap((file) => chipDrawingIn(sources[file]!).map((kind) => `${file}: ${kind}`));
    expect(drawing).toEqual([]);
  });

  it("names the chip and marks it in EvtxKindChip.tsx alone", () => {
    const marking = files
      .filter((file) => file !== CHIP_FILE)
      .flatMap((file) => chipMarkersIn(sources[file]!).map((kind) => `${file}: ${kind}`));
    expect(marking).toEqual([]);
  });

  it("keeps the allow-list small and live: every entry still writes the kind, and the chip does", () => {
    for (const file of Object.keys(ALLOWED_TO_WRITE_THE_KIND)) {
      expect(chipDrawingIn(sources[file]!).length, `${file} no longer writes EVT or LOG: drop it from the list`).toBeGreaterThan(0);
    }
    expect(chipDrawingIn(sources[CHIP_FILE]!).length).toBeGreaterThan(0);
    expect(Object.keys(ALLOWED_TO_WRITE_THE_KIND).length).toBeLessThanOrEqual(3);
  });

  it("has the timeline, the Details context and the unplaced list hand their kind to the chip", () => {
    for (const file of ["UnifiedTimelineView.tsx", "EvtxDetailContext.tsx", "EvtxUnplacedList.tsx"]) {
      expect(sources[file], file).toMatch(/<EvtxKindChip\b[^>]*\bchip=\{/);
    }
  });
});
