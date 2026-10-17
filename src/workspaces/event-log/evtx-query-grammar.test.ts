import { describe, expect, it } from "vitest";
import {
  EVTX_QUERY_FIELDS,
  parseFieldQuery,
  type EvtxFieldQuery,
  type EvtxQueryError,
  type EvtxQueryTerm,
} from "./evtx-query-grammar";

function parsed(text: string): EvtxFieldQuery {
  const result = parseFieldQuery(text);
  if (!result.ok) throw new Error(`Expected "${text}" to parse: ${result.error.message}`);
  return result.query;
}

function failure(text: string): EvtxQueryError {
  const result = parseFieldQuery(text);
  if (result.ok) throw new Error(`Expected "${text}" to fail`);
  return result.error;
}

/** Each clause as a list of terms written back in a compact, comparable form. */
function shape(text: string): string[][] {
  const written = (term: EvtxQueryTerm) => {
    const sign = term.negated ? "-" : "";
    switch (term.kind) {
      case "text":
        return `${sign}text(${term.value})`;
      case "field":
        return `${sign}${term.field}(${term.value})`;
      case "data":
        return `${sign}data.${term.name}(${term.value})`;
    }
  };
  return parsed(text).clauses.map((clause) => clause.map(written));
}

describe("parseFieldQuery: terms", () => {
  it("parses blank text to no clauses", () => {
    expect(parsed("").clauses).toEqual([]);
    expect(parsed("   \t ").clauses).toEqual([]);
  });

  it("reads bare words as free text, each its own clause (terms are ANDed)", () => {
    expect(shape("Boot  completed")).toEqual([["text(Boot)"], ["text(completed)"]]);
  });

  it("reads every field the spec lists, with the field name case-insensitive", () => {
    expect(EVTX_QUERY_FIELDS).toEqual(["id", "level", "provider", "channel", "computer", "source"]);
    expect(
      shape("ID:76 Level:Error PROVIDER:AAD channel:System Computer:PC-01 source:app.log"),
    ).toEqual([
      ["id(76)"],
      ["level(Error)"],
      ["provider(AAD)"],
      ["channel(System)"],
      ["computer(PC-01)"],
      ["source(app.log)"],
    ]);
  });

  it("reads data.<Name> case-insensitively and keeps the name as typed", () => {
    expect(shape("data.TargetUserName:admin DATA.Data1:0x5")).toEqual([
      ["data.TargetUserName(admin)"],
      ["data.Data1(0x5)"],
    ]);
  });

  it("parses the placeholder's example query", () => {
    expect(shape("id:76  level:error  provider:AAD")).toEqual([
      ["id(76)"],
      ["level(error)"],
      ["provider(AAD)"],
    ]);
  });

  it("keeps an Event ID list or range as one value for the filter to read", () => {
    expect(shape("id:1098,1014 id:4624-4634")).toEqual([["id(1098,1014)"], ["id(4624-4634)"]]);
  });

  it("records where each term and its value start", () => {
    const [[negated], [quoted]] = parsed('-id:7036 provider:"Service Control"').clauses;
    expect(negated).toMatchObject({ position: 0, valuePosition: 4, value: "7036" });
    expect(quoted).toMatchObject({ position: 9, valuePosition: 19, value: "Service Control" });
  });
});

describe("parseFieldQuery: OR", () => {
  it("joins the terms on either side into one clause", () => {
    expect(shape("provider:DeviceManagement OR id:1098,1014")).toEqual([
      ["provider(DeviceManagement)", "id(1098,1014)"],
    ]);
  });

  it("binds tighter than the implicit AND: a b OR c d is a AND (b OR c) AND d", () => {
    expect(shape("a b OR c d")).toEqual([["text(a)"], ["text(b)", "text(c)"], ["text(d)"]]);
    expect(shape("a OR b OR c")).toEqual([["text(a)", "text(b)", "text(c)"]]);
  });

  it("treats lower-case or, a quoted OR and a negated OR as text", () => {
    expect(shape('a or b "OR" -OR')).toEqual([
      ["text(a)"],
      ["text(or)"],
      ["text(b)"],
      ["text(OR)"],
      ["-text(OR)"],
    ]);
  });

  it("rejects an OR with no term on one side, at the OR", () => {
    expect(failure("OR a")).toEqual({
      position: 0,
      message: '"OR" at character 1 needs a term on each side.',
    });
    expect(failure("a OR")).toMatchObject({ position: 2 });
    expect(failure("a OR OR b")).toMatchObject({ position: 5 });
    expect(failure("OR")).toMatchObject({ position: 0 });
  });
});

describe("parseFieldQuery: negation and hyphens", () => {
  it("negates a field term or a text term with a leading -", () => {
    expect(shape('-level:verbose -"access denied" -data.Status:0x0')).toEqual([
      ["-level(verbose)"],
      ["-text(access denied)"],
      ["-data.Status(0x0)"],
    ]);
  });

  it("keeps a hyphen inside a word or value literal", () => {
    expect(shape("Kernel-Power provider:Microsoft-Windows-Kernel-Power")).toEqual([
      ["text(Kernel-Power)"],
      ["provider(Microsoft-Windows-Kernel-Power)"],
    ]);
  });

  it("negates only the first hyphen", () => {
    expect(shape("--x")).toEqual([["-text(-x)"]]);
  });

  it("rejects a - with nothing after it, at the -", () => {
    expect(failure("-")).toEqual({
      position: 0,
      message: 'Nothing to exclude after "-" at character 1.',
    });
    expect(failure("boot - failed")).toMatchObject({ position: 5 });
    expect(failure("boot -")).toMatchObject({ position: 5 });
  });
});

describe("parseFieldQuery: quotes", () => {
  it("reads a quoted phrase as one text term and a quoted value as one value", () => {
    expect(shape('"Boot completed" provider:"Service Control Manager"')).toEqual([
      ["text(Boot completed)"],
      ["provider(Service Control Manager)"],
    ]);
  });

  it("keeps spaces and colons inside quotes", () => {
    expect(shape('"Event ID: 7036"')).toEqual([["text(Event ID: 7036)"]]);
  });

  it("rejects an unclosed quote at the quote", () => {
    expect(failure('boot "failed')).toEqual({
      position: 5,
      message: "The quote at character 6 is not closed.",
    });
    expect(failure('provider:"Service')).toMatchObject({ position: 9 });
  });

  it("rejects text run on after a closing quote, where it starts", () => {
    expect(failure('"abc"def')).toEqual({
      position: 5,
      message: "Add a space after the closing quote at character 5.",
    });
  });

  it("rejects a quote inside a word, at the quote", () => {
    expect(failure('abc"def"')).toEqual({
      position: 3,
      message: "Unexpected quote at character 4. Quotes go around a whole term or value.",
    });
    expect(failure('provider:AA"D"')).toMatchObject({ position: 11 });
  });

  it("rejects empty quotes rather than reading them as a term that matches everything", () => {
    expect(failure('boot ""')).toEqual({
      position: 5,
      message: "The quotes at character 6 are empty.",
    });
  });
});

describe("parseFieldQuery: colons in free text", () => {
  it.each([
    ["C:\\Windows\\System32", "C:\\Windows\\System32"],
    ["http://contoso.example/path", "http://contoso.example/path"],
    ["12:00:01", "12:00:01"],
    ["Status:0xC000006D", "Status:0xC000006D"],
    // A misspelt field is not a field: it is text that matches only records containing it.
    ["providr:AAD", "providr:AAD"],
    ["data:x", "data:x"],
  ])("reads %s as free text, because the text before the colon is not a field", (text, value) => {
    expect(shape(text)).toEqual([[`text(${value})`]]);
  });
});

describe("parseFieldQuery: field errors", () => {
  it("rejects a field with no value, at the term", () => {
    expect(failure("level:")).toEqual({ position: 0, message: "level: needs a value." });
    expect(failure("boot -level: error")).toEqual({
      position: 5,
      message: "level: needs a value.",
    });
    expect(failure('provider:""')).toEqual({ position: 0, message: "provider: needs a value." });
    expect(failure("data.Status:")).toEqual({ position: 0, message: "data.Status: needs a value." });
  });

  it("asks for the field name after data.", () => {
    expect(failure("data.:admin")).toEqual({
      position: 0,
      message: "data. needs a field name, as in data.TargetUserName:admin.",
    });
  });

  it("reports the first problem only, and parses nothing of a malformed query", () => {
    const result = parseFieldQuery('level:error "unclosed OR');
    expect(result.ok).toBe(false);
    expect(result).not.toHaveProperty("query");
  });
});
