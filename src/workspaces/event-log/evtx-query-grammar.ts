/**
 * The field-scoped search grammar (spec section 8.3, issue #833): the syntax of a query such as
 * `provider:DeviceManagement OR id:1098,1014 -level:verbose`.
 *
 * Syntax only. This module turns text into terms, and reports malformed text with the offset where
 * it goes wrong. It does not know what an Event ID list or a level name is: `evtx-filter.ts` gives
 * each term its meaning, because the Event ID grammar (`parseEventIdSelectors`) and the level list
 * (`EVTX_LEVELS`) live there with other consumers, and importing them here would close an import
 * cycle with the module that evaluates queries.
 *
 *   query   = [ clause { space clause } ]          every clause must match (AND)
 *   clause  = term { space "OR" space term }       any one term may match; OR binds tighter
 *   term    = [ "-" ] ( field ":" value | text )   "-" excludes what the term matches
 *   field   = "id" | "level" | "provider" | "channel" | "computer" | "source" | "data." name
 *   name    = char-not-space-colon-quote { char-not-space-colon-quote }
 *   value   = quoted | bare
 *   text    = quoted | bare
 *   quoted  = '"' { char-not-quote } '"'           followed by a space or the end
 *   bare    = char-not-space-quote { char-not-space-quote }
 *
 * - Field names, `data.` included, are case-insensitive.
 * - A word whose text before its first colon is not a field (`C:\Windows`, `http://host`,
 *   `12:00:01`) is free text, colon and all.
 * - "OR" is the operator only in upper case, unquoted, not negated and standing alone. `or`,
 *   `"OR"` and `-OR` are text.
 * - A quote opens only a whole term or a whole value, and there is no escape inside one. There
 *   are no parentheses: `(` is an ordinary character.
 */

/** The fields a term can name, other than `data.<Name>`. */
export const EVTX_QUERY_FIELDS = [
  "id",
  "level",
  "provider",
  "channel",
  "computer",
  "source",
] as const;

export type EvtxQueryField = (typeof EVTX_QUERY_FIELDS)[number];

const DATA_PREFIX = "data.";

interface EvtxQueryTermBase {
  /** True for a term written with a leading "-": it matches what the bare term does not. */
  negated: boolean;
  /** The text or value with any quotes removed. Never empty. */
  value: string;
  /** Offset of the term's first character, the "-" when negated. */
  position: number;
  /** Offset of the value's first character, inside any opening quote. */
  valuePosition: number;
}

export type EvtxQueryTerm = EvtxQueryTermBase &
  (
    | { kind: "text" }
    | { kind: "field"; field: EvtxQueryField }
    /** An EventData field, `data.<Name>:`. The name keeps the operator's spelling. */
    | { kind: "data"; name: string }
  );

/** Every clause must match; a clause matches when any of its terms does. */
export interface EvtxFieldQuery {
  clauses: EvtxQueryTerm[][];
}

export interface EvtxQueryError {
  /** Offset into the query text where the problem starts. */
  position: number;
  /** One sentence, written for the operator. */
  message: string;
}

export type EvtxFieldQueryParse =
  | { ok: true; query: EvtxFieldQuery }
  | { ok: false; error: EvtxQueryError };

type Token =
  | { kind: "term"; term: EvtxQueryTerm; end: number }
  | { kind: "or"; position: number; end: number }
  | { kind: "error"; error: EvtxQueryError };

function isSpace(char: string | undefined): boolean {
  return char !== undefined && /\s/.test(char);
}

/** 1-based, the way a person counts characters. */
function characterNumber(offset: number): number {
  return offset + 1;
}

function fail(position: number, message: string): { kind: "error"; error: EvtxQueryError } {
  return { kind: "error", error: { position, message } };
}

type QuotedRead =
  | { kind: "quoted"; value: string; end: number }
  | { kind: "error"; error: EvtxQueryError };

/** Reads a quoted run starting at the quote at `open`. */
function readQuoted(text: string, open: number): QuotedRead {
  const close = text.indexOf('"', open + 1);
  if (close < 0) {
    return fail(open, `The quote at character ${characterNumber(open)} is not closed.`);
  }
  const end = close + 1;
  if (end < text.length && !isSpace(text[end])) {
    return fail(
      end,
      `Add a space after the closing quote at character ${characterNumber(close)}.`,
    );
  }
  return { kind: "quoted", value: text.slice(open + 1, close), end };
}

/** Reads an unquoted run from `start` to the next space; a quote inside it is an error. */
function readBare(
  text: string,
  start: number,
): { kind: "bare"; value: string; end: number } | { kind: "error"; error: EvtxQueryError } {
  let end = start;
  while (end < text.length && !isSpace(text[end])) {
    if (text[end] === '"') {
      return fail(
        end,
        `Unexpected quote at character ${characterNumber(end)}. Quotes go around a whole term or value.`,
      );
    }
    end++;
  }
  return { kind: "bare", value: text.slice(start, end), end };
}

type FieldPrefix =
  | { kind: "field"; field: EvtxQueryField }
  | { kind: "data"; name: string }
  | { kind: "dataWithoutName" };

function resolveFieldPrefix(prefix: string): FieldPrefix | null {
  const lower = prefix.toLowerCase();
  const field = EVTX_QUERY_FIELDS.find((candidate) => candidate === lower);
  if (field) return { kind: "field", field };
  if (lower.startsWith(DATA_PREFIX)) {
    const name = prefix.slice(DATA_PREFIX.length);
    return name ? { kind: "data", name } : { kind: "dataWithoutName" };
  }
  return null;
}

/** Reads one term, or an OR, starting at a character that is not a space. */
function readToken(text: string, start: number): Token {
  let cursor = start;
  const negated = text[cursor] === "-";
  if (negated) {
    cursor++;
    if (cursor >= text.length || isSpace(text[cursor])) {
      return fail(start, `Nothing to exclude after "-" at character ${characterNumber(start)}.`);
    }
  }

  if (text[cursor] === '"') {
    const quoted = readQuoted(text, cursor);
    if (quoted.kind === "error") return quoted;
    if (!quoted.value) {
      return fail(cursor, `The quotes at character ${characterNumber(cursor)} are empty.`);
    }
    return {
      kind: "term",
      term: { kind: "text", negated, value: quoted.value, position: start, valuePosition: cursor + 1 },
      end: quoted.end,
    };
  }

  // A field prefix is the run before a colon, with no space or quote in it.
  let colon = cursor;
  while (
    colon < text.length &&
    !isSpace(text[colon]) &&
    text[colon] !== ":" &&
    text[colon] !== '"'
  ) {
    colon++;
  }
  const prefix = text[colon] === ":" ? resolveFieldPrefix(text.slice(cursor, colon)) : null;
  if (prefix) {
    if (prefix.kind === "dataWithoutName") {
      return fail(start, "data. needs a field name, as in data.TargetUserName:admin.");
    }
    const label = prefix.kind === "field" ? `${prefix.field}:` : `${DATA_PREFIX}${prefix.name}:`;
    const valueStart = colon + 1;
    if (valueStart >= text.length || isSpace(text[valueStart])) {
      return fail(start, `${label} needs a value.`);
    }
    const read =
      text[valueStart] === '"' ? readQuoted(text, valueStart) : readBare(text, valueStart);
    if (read.kind === "error") return read;
    if (!read.value) return fail(start, `${label} needs a value.`);
    const valuePosition = read.kind === "quoted" ? valueStart + 1 : valueStart;
    const base = { negated, value: read.value, position: start, valuePosition };
    return {
      kind: "term",
      term:
        prefix.kind === "field"
          ? { ...base, kind: "field", field: prefix.field }
          : { ...base, kind: "data", name: prefix.name },
      end: read.end,
    };
  }

  const bare = readBare(text, cursor);
  if (bare.kind === "error") return bare;
  if (!negated && bare.value === "OR") return { kind: "or", position: start, end: bare.end };
  return {
    kind: "term",
    term: { kind: "text", negated, value: bare.value, position: start, valuePosition: cursor },
    end: bare.end,
  };
}

/**
 * Parses a field query. Blank text parses to no clauses, which constrains nothing; whether blank
 * text is a filter at all is the caller's decision.
 */
export function parseFieldQuery(text: string): EvtxFieldQueryParse {
  const clauses: EvtxQueryTerm[][] = [];
  // The offset of an OR still waiting for the term on its right.
  let pendingOr: number | null = null;
  const orNeedsTerms = (position: number): EvtxFieldQueryParse => ({
    ok: false,
    error: {
      position,
      message: `"OR" at character ${characterNumber(position)} needs a term on each side.`,
    },
  });

  let cursor = 0;
  for (;;) {
    while (isSpace(text[cursor])) cursor++;
    if (cursor >= text.length) break;
    const token = readToken(text, cursor);
    if (token.kind === "error") return { ok: false, error: token.error };
    if (token.kind === "or") {
      if (clauses.length === 0 || pendingOr !== null) return orNeedsTerms(token.position);
      pendingOr = token.position;
    } else if (pendingOr !== null) {
      clauses[clauses.length - 1].push(token.term);
      pendingOr = null;
    } else {
      clauses.push([token.term]);
    }
    cursor = token.end;
  }
  if (pendingOr !== null) return orNeedsTerms(pendingOr);
  return { ok: true, query: { clauses } };
}
