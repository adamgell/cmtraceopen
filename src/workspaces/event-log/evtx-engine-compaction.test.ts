/**
 * The matchers that read the engine's own text compaction, held to the engine's bytes.
 *
 * `__fixtures__/engine-compaction-vectors.json` is what the Rust functions printed (timeline.rs
 * `compact_timeline_text`, `origin_of` with `compact_timeline_origin`; analysis_session.rs
 * `compact_display_text`, `diagnosis_record_identity` with `sanitize_malformed_timeline_record`),
 * and three Rust tests recompute every case, so this file cannot drift from the engine without a
 * Rust test failing too. `engineCompactReference` below is a SECOND, independent statement of the
 * format (bytes and BigInt, not the production scan); it is checked against the vectors before it
 * is used for anything the vectors do not cover.
 *
 * The constants and the format string are pinned in the Rust source by
 * `evtx-engine-compaction-pin.test.ts`.
 */
import { describe, expect, it } from "vitest";
import { boundUtf8WithDigest } from "../../lib/bounded-utf8";
import vectorDocument from "./__fixtures__/engine-compaction-vectors.json";
import { provenanceAgrees, normalizedProvenance } from "./evtx-correlation-origin-index";
import {
  TIMELINE_LIMIT,
  displayReference,
  referenceDigest,
  timelineReference,
} from "./evtx-engine-compaction-test-fixtures";
import {
  engineRecordIdentity,
  engineTimelineRecordIdentity,
  evidenceTextMatches,
  timelineTextMatches,
} from "./evtx-insights-data";
import type { EvtxRecord } from "./types";

interface TextCase {
  name: string;
  input: string;
  compacted: string;
  changed: boolean;
  inputBytes: number;
}

interface OriginCase {
  name: string;
  originKind: "event" | "log";
  sourceLabel: string;
  channel: string;
  provider: string;
  computer: string;
  origin: {
    kind: "event" | "log";
    source: string;
    machine: string | null;
    channel?: string;
    provider?: string;
    file?: string;
    component?: string | null;
  };
}

interface IdentityCase {
  name: string;
  originKind: "event" | "log";
  text: string | null;
  id: number;
  malformed: boolean;
  originRecordIdText: string | null;
  originRecordId: number;
}

const vectors = vectorDocument as unknown as {
  timelineText: TextCase[];
  displayText: TextCase[];
  origins: OriginCase[];
  identities: IdentityCase[];
};

describe("the reference format and the engine's vectors", () => {
  it.each(vectors.timelineText.map((c) => [c.name, c] as const))(
    "reproduces the engine's timeline compaction of %s",
    (_name, c) => {
      expect(timelineReference(c.input)).toBe(c.compacted);
      expect(new TextEncoder().encode(c.input).length).toBe(c.inputBytes);
    },
  );

  it.each(vectors.displayText.map((c) => [c.name, c] as const))(
    "reproduces the engine's diagnosis display compaction of %s",
    (_name, c) => {
      expect(displayReference(c.input)).toBe(c.compacted);
    },
  );

  it("covers the cases that matter: 257 and 300 bytes, CJK, and a character cut at the boundary", () => {
    const names = vectors.timelineText.map((c) => c.name);
    expect(names).toEqual(
      expect.arrayContaining([
        "ascii-256-unchanged",
        "ascii-257",
        "ascii-300-backslashes",
        "bundle-path-276",
        "cjk-273",
        "two-byte-300",
        "emoji-290",
      ]),
    );
    // The engine cut these back to a character boundary, so the result is under the limit.
    const bytesOf = (text: string) => new TextEncoder().encode(text).length;
    for (const name of ["cjk-273", "two-byte-300", "emoji-290"]) {
      const c = vectors.timelineText.find((entry) => entry.name === name) as TextCase;
      expect(bytesOf(c.compacted)).toBeLessThan(TIMELINE_LIMIT);
    }
  });
});

describe("timelineTextMatches: an origin text the engine compacted", () => {
  const changed = vectors.timelineText.filter((c) => c.changed);

  it.each(changed.map((c) => [c.name, c] as const))("names the record value for %s", (_name, c) => {
    expect(timelineTextMatches(c.compacted, c.input)).toBe(true);
  });

  it("keeps short text exact", () => {
    const unchanged = vectors.timelineText.find((c) => c.name === "ascii-256-unchanged") as TextCase;
    expect(unchanged.compacted).toBe(unchanged.input);
    expect(timelineTextMatches(unchanged.compacted, unchanged.input)).toBe(true);
    expect(timelineTextMatches(unchanged.compacted, `${unchanged.input}x`)).toBe(false);
    expect(timelineTextMatches("Live", "Live")).toBe(true);
    expect(timelineTextMatches("Live", "Live ")).toBe(false);
  });

  it.each(changed.map((c) => [c.name, c] as const))(
    "does not name a record that has the same prefix and another length (%s)",
    (_name, c) => {
      // One more character: the prefix is the same, the length is not.
      expect(timelineTextMatches(c.compacted, `${c.input}x`)).toBe(false);
    },
  );

  it.each(changed.map((c) => [c.name, c] as const))(
    "does not name a record that has the same prefix and length but another digest (%s)",
    (_name, c) => {
      // The last character swapped for another of the same width: same length, same prefix.
      const lastChar = [...c.input].pop() as string;
      const swapped = `${c.input.slice(0, c.input.length - lastChar.length)}${lastChar === "q" ? "r" : "q"}`;
      if (new TextEncoder().encode(swapped).length !== c.inputBytes) return;
      expect(timelineTextMatches(c.compacted, swapped)).toBe(false);
    },
  );

  it("rejects a suffix whose length is not the record's, whatever else agrees", () => {
    const c = vectors.timelineText.find((entry) => entry.name === "ascii-300-backslashes") as TextCase;
    const forged = c.compacted.replace("[300 bytes;", "[301 bytes;");
    expect(forged).not.toBe(c.compacted);
    expect(timelineTextMatches(forged, c.input)).toBe(false);
  });

  it("rejects a suffix whose digest is not the record's, whatever else agrees", () => {
    const c = vectors.timelineText.find((entry) => entry.name === "ascii-300-backslashes") as TextCase;
    const digest = /digest=([0-9a-f]{16})\]$/.exec(c.compacted)?.[1] as string;
    const flipped = `${digest.slice(0, 15)}${digest.endsWith("0") ? "1" : "0"}`;
    expect(timelineTextMatches(c.compacted.replace(digest, flipped), c.input)).toBe(false);
  });

  it("rejects a prefix that is not the record's", () => {
    const c = vectors.timelineText.find((entry) => entry.name === "ascii-300-backslashes") as TextCase;
    expect(timelineTextMatches(`Z${c.compacted.slice(1)}`, c.input)).toBe(false);
  });

  it("rejects a prefix cut at the wrong place, one character short or one long", () => {
    const c = vectors.timelineText.find((entry) => entry.name === "ascii-300-backslashes") as TextCase;
    const suffixAt = c.compacted.lastIndexOf("...[");
    const prefix = c.compacted.slice(0, suffixAt);
    const suffix = c.compacted.slice(suffixAt);
    expect(timelineTextMatches(`${prefix.slice(0, -1)}${suffix}`, c.input)).toBe(false);
    expect(timelineTextMatches(`${prefix}${c.input[prefix.length] as string}${suffix}`, c.input)).toBe(false);
  });

  it("does not take a suffix on a value that is not over the limit as a compaction", () => {
    // The engine leaves up to 256 bytes alone, so a length of 256 or less in a suffix is not its work.
    const forged = "abc...[10 bytes; digest=0000000000000000]";
    expect(timelineTextMatches(forged, "abcdefghij")).toBe(false);
    // Even with the right length, the right digest and the right prefix for its length.
    const raw = "a".repeat(250);
    const suffix = `...[250 bytes; digest=${referenceDigest(new TextEncoder().encode(raw), true)}]`;
    const forgedFromShortValue = `${raw.slice(0, TIMELINE_LIMIT - suffix.length)}${suffix}`;
    expect(timelineTextMatches(forgedFromShortValue, raw)).toBe(false);
  });

  it("does not take the diagnosis display form, which is another format", () => {
    const display = vectors.displayText.find((c) => c.name === "ascii-5000") as TextCase;
    expect(timelineTextMatches(display.compacted, display.input)).toBe(false);
  });

  it("still takes the transport's bound on a record the transport projected", () => {
    const long = `C:/Cases/${"y".repeat(400)}`;
    const projected = boundUtf8WithDigest(long, 256);
    expect(projected).toMatch(/\u2026\[truncated:[0-9a-f]{16}\]$/);
    expect(timelineTextMatches(projected, long)).toBe(true);
    expect(timelineTextMatches(projected, `${long}z`)).toBe(false);
  });

  it("matches the reference over a sweep of lengths and character widths", () => {
    // A small seeded generator, so a failure names a value that can be rebuilt.
    let state = 0x2545_f491;
    const next = () => {
      state = (Math.imul(state ^ (state >>> 15), 0x2c1b_3c6d) + 0x9e37_79b9) >>> 0;
      return state;
    };
    const alphabets = [
      ["a", "b", "/", "\\", " ", "-", "0"],
      ["\u00e9", "\u00fc", "a"],
      ["\u6848", "\u4ef6", "/"],
      ["\u{1f600}", "\u{1d4b3}", "x"],
    ];
    let compactedCount = 0;
    for (let round = 0; round < 160; round += 1) {
      const alphabet = alphabets[round % alphabets.length] as string[];
      const target = 240 + (next() % 140);
      let value = "";
      while (new TextEncoder().encode(value).length < target) {
        value += alphabet[next() % alphabet.length] as string;
      }
      const compacted = timelineReference(value);
      expect(timelineTextMatches(compacted, value), `round ${round}`).toBe(true);
      if (compacted !== value) {
        compactedCount += 1;
        expect(timelineTextMatches(compacted, `${value}a`), `round ${round} longer`).toBe(false);
        expect(timelineTextMatches(compacted, value.slice(0, -1)), `round ${round} shorter`).toBe(false);
      }
    }
    expect(compactedCount).toBeGreaterThan(80);
  });
});

describe("provenanceAgrees: machine and component are normalized, then compared", () => {
  const origins = vectors.origins;
  const byName = (name: string) => origins.find((c) => c.name === name) as OriginCase;

  it("takes a machine that is padded past the limit and fits once trimmed, which the engine does not compact", () => {
    const c = byName("padded-machine-fits");
    expect(new TextEncoder().encode(c.computer).length).toBeGreaterThan(TIMELINE_LIMIT);
    expect(c.origin.machine).toBe(c.computer.trim());
    expect(provenanceAgrees(c.origin.machine, c.computer)).toBe(true);
  });

  it("takes a machine that is over the limit once trimmed, compacted from the TRIMMED text", () => {
    const c = byName("all-long-padded");
    expect(c.origin.machine).toMatch(/\.\.\.\[300 bytes; digest=[0-9a-f]{16}\]$/);
    expect(provenanceAgrees(c.origin.machine, c.computer)).toBe(true);
  });

  it("takes a component the same way", () => {
    const padded = byName("log-component-padded");
    expect(padded.origin.component).toMatch(/\.\.\.\[300 bytes; digest=[0-9a-f]{16}\]$/);
    expect(provenanceAgrees(padded.origin.component ?? null, padded.provider)).toBe(true);
    const fits = byName("log-component-fits");
    expect(fits.origin.component).toBe(fits.provider.trim());
    expect(provenanceAgrees(fits.origin.component ?? null, fits.provider)).toBe(true);
  });

  it("finds no machine in a placeholder word, padded or not", () => {
    const c = byName("placeholder-machine");
    expect(c.origin.machine).toBeNull();
    expect(provenanceAgrees(null, c.computer)).toBe(true);
    expect(provenanceAgrees(null, "UNKNOWN")).toBe(true);
    expect(provenanceAgrees(null, "  not available  ")).toBe(true);
    expect(provenanceAgrees(null, "DESKTOP-01")).toBe(false);
    expect(provenanceAgrees("DESKTOP-01", "n/a")).toBe(false);
  });

  it("does not take another machine, however long", () => {
    const c = byName("all-long-padded");
    expect(provenanceAgrees(c.origin.machine, `${c.computer}Z`)).toBe(false);
    expect(provenanceAgrees(c.origin.machine, c.computer.replace("NNN", "NNM"))).toBe(false);
    expect(provenanceAgrees("HOST-A", "  HOST-B  ")).toBe(false);
    expect(provenanceAgrees("HOST-A", "  HOST-A  ")).toBe(true);
  });

  it("takes a record the transport projected, whose machine reached the engine already bounded", () => {
    const long = `HOST-${"M".repeat(400)}`;
    const projected = boundUtf8WithDigest(long, 256);
    expect(provenanceAgrees(projected, long)).toBe(true);
    expect(provenanceAgrees(projected, `${long}x`)).toBe(false);
  });

  it("normalizes as the engine's normalized_provenance does", () => {
    expect(normalizedProvenance("  HOST  ")).toBe("HOST");
    expect(normalizedProvenance("  ")).toBeNull();
    for (const word of ["unknown", "N/A", "na", "None", "NULL", "Not Available", "not_applicable"]) {
      expect(normalizedProvenance(` ${word} `)).toBeNull();
    }
    expect(normalizedProvenance("unknown-host")).toBe("unknown-host");
  });
});

describe("evidenceTextMatches: the diagnosis display compaction", () => {
  const ascii5000 = vectors.displayText.find((c) => c.name === "ascii-5000") as TextCase;
  const cjk = vectors.displayText.find((c) => c.name === "cjk-4101") as TextCase;
  const emoji = vectors.displayText.find((c) => c.name === "emoji-4200") as TextCase;

  it.each([
    ["ASCII", ascii5000],
    ["3-byte characters cut back to a boundary", cjk],
    ["4-byte characters cut back to a boundary", emoji],
  ])("names the record value of %s", (_name, c) => {
    expect(c.changed).toBe(true);
    expect(evidenceTextMatches(c.compacted, c.input)).toBe(true);
  });

  it("keeps text under the limit exact", () => {
    const short = vectors.displayText.find((c) => c.name === "ascii-300-unchanged") as TextCase;
    expect(evidenceTextMatches(short.compacted, short.input)).toBe(true);
    expect(evidenceTextMatches(short.compacted, `${short.input}z`)).toBe(false);
  });

  it("does not name a record with another length, digest or prefix", () => {
    expect(evidenceTextMatches(ascii5000.compacted, `${ascii5000.input}x`)).toBe(false);
    expect(evidenceTextMatches(ascii5000.compacted, `${ascii5000.input.slice(0, -1)}q`)).toBe(false);
    expect(evidenceTextMatches(`Z${ascii5000.compacted.slice(1)}`, ascii5000.input)).toBe(false);
  });

  it("reads the redaction tokens in the kept prefix as wildcards, as the engine redacts after it compacts", () => {
    const profile = `C:\\Users\\case.user\\Cases\\${"x".repeat(5000)}`;
    const compacted = displayReference(profile);
    const redacted = compacted.replace("case.user", "[user:0123456789abcdef]");
    expect(redacted).not.toBe(compacted);
    expect(evidenceTextMatches(redacted, profile)).toBe(true);
    expect(evidenceTextMatches(redacted, profile.replace("case.user", "someone.el"))).toBe(false);
  });

  it("does not take the timeline form, which is another format", () => {
    const timeline = vectors.timelineText.find((c) => c.name === "ascii-300-backslashes") as TextCase;
    expect(evidenceTextMatches(timeline.compacted, timeline.input)).toBe(false);
  });
});

describe("engineTimelineRecordIdentity: the identity the engine puts on the origin", () => {
  const record = (text: string | null, id: number, originKind: "event" | "log"): EvtxRecord =>
    ({
      id: 1,
      eventRecordId: id,
      eventRecordIdText: text,
      eventId: 1,
      originKind,
    }) as unknown as EvtxRecord;

  it.each(vectors.identities.map((c) => [c.name, c] as const))(
    "predicts the engine's origin for %s",
    (_name, c) => {
      const predicted = engineTimelineRecordIdentity(record(c.text, c.id, c.originKind));
      if (c.originKind === "log") {
        // A text-log record is never rewritten and its origin carries no record text.
        expect(predicted).toBe(engineRecordIdentity(c.text, c.id));
        return;
      }
      expect(predicted).toBe(engineRecordIdentity(c.originRecordIdText, c.originRecordId));
    },
  );

  it("names the identity the record reading alone gets wrong, which is why it exists", () => {
    const wrong = vectors.identities
      .filter((c) => c.originKind === "event")
      .filter((c) => engineRecordIdentity(c.text, c.id) !== engineRecordIdentity(c.originRecordIdText, c.originRecordId))
      .map((c) => c.name);
    expect(wrong).toEqual(
      expect.arrayContaining([
        "padded-text-other-number",
        "conflict-positive-number",
        "conflict-zero-number",
        "outside-u64-with-number",
        "outside-u64-without-number",
        "unsafe-number-without-text",
      ]),
    );
  });

  it("agrees with the engine's own malformed flag only where the flag changes the identity", () => {
    // A refused identity that the rewrite leaves unchanged (a padded text of the same number) is
    // still refused, and the origin is the same either way.
    const same = vectors.identities.find((c) => c.name === "padded-text-same-number") as IdentityCase;
    expect(same.malformed).toBe(true);
    expect(engineTimelineRecordIdentity(record(same.text, same.id, "event"))).toBe("7");
  });

  it("gives no identity to a record the transport could not send", () => {
    expect(engineTimelineRecordIdentity(record(null, -1, "event"))).toBeNull();
    expect(engineTimelineRecordIdentity(record(null, 1.5, "event"))).toBeNull();
    expect(engineTimelineRecordIdentity(record(null, Number.NaN, "event"))).toBeNull();
  });
});
