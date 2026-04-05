import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { describe, expect, it, vi, beforeEach } from "vitest";
import { writeText } from "@tauri-apps/plugin-clipboard-manager";
import { EventTimelineRow } from "./EventTimelineRow";
import type { IntuneEvent } from "./types";

describe("EventTimelineRow", () => {
  beforeEach(() => {
    vi.mocked(writeText).mockReset();
  });

  it("copies the selected failed event with context to the clipboard", async () => {
    const onSelect = vi.fn();
    const event: IntuneEvent = {
      id: 7,
      eventType: "ContentDownload",
      name: "AppWorkload Download Retry - Contoso App",
      guid: "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
      status: "Failed",
      startTime: "2026-04-01T19:00:42.578Z",
      endTime: null,
      durationSecs: null,
      errorCode: "0x87D30067",
      detail: [
        "Download failed for app id: a1b2c3d4-e5f6-7890-abcd-ef1234567890 with error code = 0x87D30067",
        "",
        "AppWorkload context:",
        "  L11 2026-04-01T19:00:41.000Z [Win32App][V3Processor] Processing subgraph with app ids: a1b2c3d4-e5f6-7890-abcd-ef1234567890",
        "> L12 2026-04-01T19:00:42.578Z Download failed for app id: a1b2c3d4-e5f6-7890-abcd-ef1234567890 with error code = 0x87D30067",
      ].join("\n"),
      sourceFile: "C:/Logs/AppWorkload.log",
      lineNumber: 12,
      startTimeEpoch: 1711998042578,
      endTimeEpoch: null,
    };

    render(
      <EventTimelineRow
        event={event}
        dataIndex={0}
        isSelected
        fontSize={13}
        smallFontSize={10}
        monoFontSize={11}
        lineHeight="18px"
        rowLineHeightExpanded={20}
        showSourceFileLabel={false}
        onSelect={onSelect}
      />
    );

    fireEvent.click(screen.getByRole("button", { name: "Copy error + context" }));

    await waitFor(() => {
      expect(writeText).toHaveBeenCalledWith(
        expect.stringContaining("Error: 0x87D30067")
      );
    });
    expect(writeText).toHaveBeenCalledWith(
      expect.stringContaining("AppWorkload context:")
    );
    expect(onSelect).not.toHaveBeenCalled();
  });
});
