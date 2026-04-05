import { memo, useCallback, useState } from "react";
import { tokens } from "@fluentui/react-components";
import { writeText } from "@tauri-apps/plugin-clipboard-manager";
import { LOG_MONOSPACE_FONT_FAMILY } from "../../lib/log-accessibility";

interface ScriptCodeViewerProps {
  script: string;
  maxHeight?: number;
}

type TokenType =
  | "comment"
  | "string"
  | "variable"
  | "keyword"
  | "cmdlet"
  | "operator"
  | "number"
  | "text";

interface Token {
  type: TokenType;
  value: string;
}

const PS_KEYWORDS = new Set([
  "function",
  "param",
  "if",
  "else",
  "elseif",
  "foreach",
  "for",
  "while",
  "do",
  "switch",
  "default",
  "try",
  "catch",
  "finally",
  "throw",
  "return",
  "break",
  "continue",
  "in",
  "begin",
  "process",
  "end",
  "filter",
  "class",
  "enum",
  "using",
  "trap",
]);

const PS_CONSTANTS = new Set([
  "$true",
  "$false",
  "$null",
  "$_",
  "$env",
  "$error",
  "$args",
  "$input",
  "$host",
  "$pid",
]);

const CMDLET_PREFIX_RE = /^[A-Z][a-z]+-[A-Z][A-Za-z]+/;

function tokenizeLine(line: string): Token[] {
  const tokens: Token[] = [];
  let i = 0;

  while (i < line.length) {
    // Block comment start
    if (line[i] === "<" && line[i + 1] === "#") {
      const end = line.indexOf("#>", i + 2);
      if (end !== -1) {
        tokens.push({ type: "comment", value: line.slice(i, end + 2) });
        i = end + 2;
      } else {
        tokens.push({ type: "comment", value: line.slice(i) });
        i = line.length;
      }
      continue;
    }

    // Line comment
    if (line[i] === "#") {
      tokens.push({ type: "comment", value: line.slice(i) });
      break;
    }

    // Single-quoted string
    if (line[i] === "'") {
      const end = line.indexOf("'", i + 1);
      if (end !== -1) {
        tokens.push({ type: "string", value: line.slice(i, end + 1) });
        i = end + 1;
      } else {
        tokens.push({ type: "string", value: line.slice(i) });
        i = line.length;
      }
      continue;
    }

    // Double-quoted string
    if (line[i] === '"') {
      let j = i + 1;
      while (j < line.length) {
        if (line[j] === "`") {
          j += 2;
          continue;
        }
        if (line[j] === '"') break;
        j++;
      }
      tokens.push({
        type: "string",
        value: line.slice(i, Math.min(j + 1, line.length)),
      });
      i = Math.min(j + 1, line.length);
      continue;
    }

    // Variable
    if (line[i] === "$") {
      let j = i + 1;
      // Handle ${...} syntax
      if (j < line.length && line[j] === "{") {
        const end = line.indexOf("}", j + 1);
        if (end !== -1) {
          const varName = line.slice(i, end + 1);
          tokens.push({ type: "variable", value: varName });
          i = end + 1;
          continue;
        }
      }
      while (j < line.length && /[A-Za-z0-9_:]/.test(line[j])) j++;
      const varName = line.slice(i, j);
      if (PS_CONSTANTS.has(varName.toLowerCase())) {
        tokens.push({ type: "keyword", value: varName });
      } else {
        tokens.push({ type: "variable", value: varName });
      }
      i = j;
      continue;
    }

    // Word (keyword, cmdlet, or plain text)
    if (/[A-Za-z_]/.test(line[i])) {
      let j = i + 1;
      while (j < line.length && /[A-Za-z0-9_-]/.test(line[j])) j++;
      const word = line.slice(i, j);
      if (PS_KEYWORDS.has(word.toLowerCase())) {
        tokens.push({ type: "keyword", value: word });
      } else if (CMDLET_PREFIX_RE.test(word)) {
        tokens.push({ type: "cmdlet", value: word });
      } else {
        tokens.push({ type: "text", value: word });
      }
      i = j;
      continue;
    }

    // Number
    if (/[0-9]/.test(line[i])) {
      let j = i + 1;
      while (j < line.length && /[0-9xXa-fA-F.]/.test(line[j])) j++;
      tokens.push({ type: "number", value: line.slice(i, j) });
      i = j;
      continue;
    }

    // Operators
    if ("-" === line[i] && i + 1 < line.length && /[a-z]/.test(line[i + 1])) {
      let j = i + 1;
      while (j < line.length && /[a-zA-Z]/.test(line[j])) j++;
      tokens.push({ type: "operator", value: line.slice(i, j) });
      i = j;
      continue;
    }

    // Other characters
    tokens.push({ type: "text", value: line[i] });
    i++;
  }

  return tokens;
}

const TOKEN_STYLES: Record<TokenType, React.CSSProperties> = {
  comment: { color: tokens.colorPaletteGreenForeground2, fontStyle: "italic" },
  string: { color: tokens.colorPaletteMarigoldForeground2 },
  variable: { color: tokens.colorPaletteBlueForeground2 },
  keyword: { color: tokens.colorPalettePurpleForeground2, fontWeight: 600 },
  cmdlet: { color: tokens.colorBrandForeground1 },
  operator: { color: tokens.colorNeutralForeground2 },
  number: { color: tokens.colorPaletteMarigoldForeground1 },
  text: {},
};

export const ScriptCodeViewer = memo(function ScriptCodeViewer({
  script,
  maxHeight = 300,
}: ScriptCodeViewerProps) {
  const [copied, setCopied] = useState(false);
  const lines = script.split("\n");

  const handleCopy = useCallback(async () => {
    try {
      await writeText(script);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch {
      // Fallback to navigator API
      try {
        await navigator.clipboard.writeText(script);
        setCopied(true);
        setTimeout(() => setCopied(false), 2000);
      } catch {
        // Ignore clipboard errors
      }
    }
  }, [script]);

  const gutterWidth = `${Math.max(String(lines.length).length * 8 + 12, 32)}px`;

  return (
    <div
      style={{
        position: "relative",
        maxHeight: `${maxHeight}px`,
        overflow: "auto",
        backgroundColor: tokens.colorNeutralBackground3,
        border: `1px solid ${tokens.colorNeutralStroke1}`,
        borderRadius: "4px",
        marginTop: "8px",
      }}
    >
      <button
        type="button"
        onClick={(e) => {
          e.stopPropagation();
          handleCopy();
        }}
        style={{
          position: "sticky",
          top: "4px",
          float: "right",
          margin: "4px",
          padding: "2px 8px",
          fontSize: "11px",
          border: `1px solid ${tokens.colorNeutralStroke1}`,
          borderRadius: "3px",
          backgroundColor: copied
            ? tokens.colorPaletteGreenBackground2
            : tokens.colorNeutralBackground1,
          color: copied
            ? tokens.colorPaletteGreenForeground1
            : tokens.colorNeutralForeground2,
          cursor: "pointer",
          zIndex: 1,
        }}
      >
        {copied ? "Copied" : "Copy"}
      </button>
      <pre
        style={{
          margin: 0,
          padding: "6px 0",
          fontFamily: LOG_MONOSPACE_FONT_FAMILY,
          fontSize: "12px",
          lineHeight: "18px",
          tabSize: 4,
        }}
      >
        {lines.map((line, idx) => (
          <div key={idx} style={{ display: "flex" }}>
            <span
              style={{
                width: gutterWidth,
                minWidth: gutterWidth,
                textAlign: "right",
                paddingRight: "8px",
                color: tokens.colorNeutralForeground4,
                userSelect: "none",
                flexShrink: 0,
              }}
            >
              {idx + 1}
            </span>
            <code style={{ flex: 1, paddingRight: "8px", whiteSpace: "pre-wrap", wordBreak: "break-all" }}>
              {tokenizeLine(line).map((tok, ti) => (
                <span key={ti} style={TOKEN_STYLES[tok.type]}>
                  {tok.value}
                </span>
              ))}
            </code>
          </div>
        ))}
      </pre>
    </div>
  );
});
