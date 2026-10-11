import { render } from "@testing-library/react";
import { describe, it, expect, vi } from "vitest";
import { LogRow } from "./LogRow";
import { getColumnDef } from "../../lib/column-config";
import { themeSeverityPalettes } from "../../lib/themes/palettes";
import type { LogEntry, Severity } from "../../types/log";

function makeEntry(severity: Severity, id = 1): LogEntry {
  return {
    id,
    lineNumber: id,
    message: `message ${id}`,
    component: null,
    timestamp: null,
    timestampDisplay: null,
    severity,
    thread: null,
    threadDisplay: null,
    sourceFile: null,
    format: "Ccm",
    filePath: "/test.log",
    timezoneOffset: null,
  };
}

const visibleColumns = [getColumnDef("severity")!, getColumnDef("message")!];

function renderRow(severity: Severity, overrides: Partial<LogEntry> = {}) {
  const palette = themeSeverityPalettes.light;
  const { container } = render(
    <LogRow
      entry={{ ...makeEntry(severity), ...overrides }}
      rowDomId="row-1"
      isSelected={false}
      isFindMatch={false}
      visibleColumns={visibleColumns}
      gridTemplateColumns="40px 1fr"
      listFontSize={13}
      rowLineHeight={18}
      severityPalette={palette}
      highlightText=""
      highlightCaseSensitive={false}
      onClick={vi.fn()}
      onContextMenu={vi.fn()}
    />
  );
  return container.querySelector('[role="option"]') as HTMLElement;
}

describe("LogRow severity rendering", () => {
  it("renders a Success row with the theme's green background and text", () => {
    const row = renderRow("Success");
    // light palette success = { background: "#DCFCE7", text: "#14532D" }
    expect(row.style.backgroundColor).toBe("rgb(220, 252, 231)");
    expect(row.style.color).toBe("rgb(20, 83, 45)");
  });

  it("labels the severity cell as Success for accessibility", () => {
    const row = renderRow("Success");
    expect(row.querySelector('[aria-label="Success"]')).not.toBeNull();
  });

  it("keeps Info rows on the neutral info background (not green)", () => {
    const row = renderRow("Info");
    // light palette info = { background: "#FFFFFF", text: "#111827" }
    expect(row.style.backgroundColor).toBe("rgb(255, 255, 255)");
  });
});

 it("identifies incomplete records without changing their raw message", () => {
   // Sanitized IME orphan suffix shape; values and payload are synthetic.
   const raw = '  suffix]LOG]!><component="Synthetic">  ';
   const row = renderRow("Info", { tags: ["cmtrace:unparsed-ime-record"], format: "Plain", message: raw });
   expect(row.querySelector('[aria-label="Unparsed"]')).not.toBeNull();
   expect(row.textContent).toContain("[Unparsed record]");
   expect(row.querySelector(".col-message")?.textContent).toContain(raw);
 });

it("does not treat arbitrary structured-log tags as IME framing diagnostics", () => {
  const row = renderRow("Info", { tags: ["cmtrace:unparsed-ime-record"], format: "CmtLog" });
  expect(row.textContent).not.toContain("[Unparsed record]");
});
