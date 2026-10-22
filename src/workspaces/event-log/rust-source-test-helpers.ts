/**
 * The one place the drift pins read a Rust item out of source text (`?raw`).
 *
 * Vite's `?raw` import gives the file exactly as the checkout wrote it. A checkout made with
 * `core.autocrlf=true` (the Git for Windows default; `.gitattributes` does not force `eol=lf` for
 * `*.rs`) has CRLF line endings, so a search written for `"\n}\n"` finds nothing there. These
 * helpers normalize CRLF to LF once on read, so a pin never sees the line endings of the machine
 * it runs on, and a pin that needs an item's text calls `itemText` rather than writing its own
 * search. The pins using them: evtx-engine-compaction-pin.test.ts, evtx-bundle-source-pin.test.ts.
 * evtx-correlation-gaps-engine.test.ts normalizes its sources through `normalizeLineEndings`.
 */

/** The text with every CRLF read as LF. A lone CR is not a line ending any checkout writes. */
export function normalizeLineEndings(text: string): string {
  return text.replace(/\r\n/g, "\n");
}

/** The text without whitespace, so reformatting does not matter. */
export const squash = (text: string): string => text.replace(/\s+/g, "");

/**
 * The text without whitespace and without `//` line comments, so a reworded comment does not
 * matter either. A `//` inside a string literal is cut too; no item a pin reads has one.
 */
export function squashCode(text: string): string {
  return squash(normalizeLineEndings(text).replace(/\/\/[^\n]*/g, ""));
}

/**
 * The text of the item that starts at `start` (a signature), through the brace that closes its body,
 * with LF line endings. Braces inside string literals and line comments do not count. It throws when
 * the signature is missing or not unique, or the body never closes.
 */
export function itemText(source: string, start: string): string {
  const text = normalizeLineEndings(source);
  const at = text.indexOf(start);
  if (at < 0) throw new Error(`the Rust source no longer has \`${start}\``);
  if (text.indexOf(start, at + 1) >= 0) throw new Error(`\`${start}\` is no longer unique`);
  let depth = 0;
  let opened = false;
  for (let index = at; index < text.length; index += 1) {
    const char = text[index] as string;
    if (char === "/" && text[index + 1] === "/") {
      while (index < text.length && text[index] !== "\n") index += 1;
    } else if (char === '"') {
      index += 1;
      while (index < text.length && text[index] !== '"') {
        if (text[index] === "\\") index += 1;
        index += 1;
      }
    } else if (char === "{") {
      depth += 1;
      opened = true;
    } else if (char === "}") {
      depth -= 1;
      if (opened && depth === 0) return text.slice(at, index + 1);
    }
  }
  throw new Error(`\`${start}\` has no closing brace`);
}

/** The value of `const NAME: usize = <expression>;`, a product of integer literals. */
export function constantValue(source: string, name: string): number {
  const found = new RegExp(`const ${name}: (?:usize|u64) = ([0-9_ *]+);`).exec(normalizeLineEndings(source));
  if (!found) throw new Error(`the Rust source no longer has \`const ${name}\` as integer literals`);
  return (found[1] as string)
    .split("*")
    .map((factor) => Number(factor.trim().replace(/_/g, "")))
    .reduce((product, factor) => product * factor, 1);
}
