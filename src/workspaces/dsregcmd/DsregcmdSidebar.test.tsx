import { act, cleanup, fireEvent, render, renderHook, screen, within } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { DsregcmdSidebar } from "./DsregcmdSidebar";
import { DsregcmdWorkspace } from "./DsregcmdWorkspace";
import { getVisibleFactRows } from "./FactGroupRenderer";
import { useDsregcmdStore } from "./dsregcmd-store";
import { useDsregcmdDerived } from "./use-dsregcmd-derived";
import {
  analysisResult,
  sourceContext as fixtureSourceContext,
} from "./dsregcmd-test-fixtures";
import { formatDisplayDateTime } from "../../lib/date-time-format";
import { useUiStore } from "../../stores/ui-store";
import type { DsregcmdSourceContext } from "./types";

vi.mock("../../hooks/use-app-actions", () => ({
  useAppActions: () => ({
    openSourceFileDialog: vi.fn(),
    openSourceFolderDialog: vi.fn(),
    pasteDsregcmdSource: vi.fn(),
    captureDsregcmdSource: vi.fn(),
    commandState: { canRefresh: false },
    refreshActiveSource: vi.fn(),
  }),
}));

vi.mock("@tanstack/react-virtual", () => ({
  useVirtualizer: ({ count }: { count: number }) => ({
    getVirtualItems: () =>
      Array.from({ length: count }, (_, index) => ({
        index,
        key: index,
        start: index * 28,
        size: 28,
      })),
    getTotalSize: () => count * 28,
    measureElement: vi.fn(),
    scrollToIndex: vi.fn(),
  }),
}));

const CAPTURED_AT = "2026-07-13T09:12:00.000Z";

function seed(overrides: Partial<DsregcmdSourceContext> = {}, withEventLogs = true) {
  const result = analysisResult();
  if (!withEventLogs) {
    result.eventLogAnalysis = null;
  }
  useDsregcmdStore
    .getState()
    .setResults("AzureAdJoined : YES", result, { ...fixtureSourceContext(), ...overrides });
  return result;
}

beforeEach(() => {
  useUiStore.setState({ currentPlatform: "windows" });
  useDsregcmdStore.getState().clear();
});

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
  useDsregcmdStore.getState().clear();
});

describe("DsregcmdSidebar source card", () => {
  it("renders the neutral badge, label, kind line, and counts for a file", () => {
    seed();
    render(<DsregcmdSidebar />);

    expect(screen.getByText("DSREGCMD")).toBeInTheDocument();
    expect(screen.getByText("dsregcmd.txt", { selector: "div" })).toBeInTheDocument();
    expect(screen.getByText("Text file \u00B7 dsregcmd.txt")).toBeInTheDocument();
    expect(screen.getByText("40 lines \u00B7 800 chars")).toBeInTheDocument();
  });

  it("shows the capture time only for a live capture that recorded one", () => {
    seed({
      source: { kind: "capture" },
      displayLabel: "Live capture",
      capturedAt: CAPTURED_AT,
    });
    render(<DsregcmdSidebar />);

    const formatted = formatDisplayDateTime(CAPTURED_AT);
    expect(formatted).not.toBeNull();
    expect(screen.getByText(`Live capture \u00B7 ${formatted}`)).toBeInTheDocument();
  });

  it("shows no time for a live capture without capturedAt", () => {
    seed({ source: { kind: "capture" }, displayLabel: "Live capture", capturedAt: null });
    render(<DsregcmdSidebar />);

    expect(screen.queryByText(/Live capture \u00B7/)).toBeNull();
    expect(screen.getAllByText("Live capture").length).toBeGreaterThan(0);
  });

  it.each([
    {
      name: "file",
      source: { kind: "file", path: "C:\\temp\\dsregcmd.txt" },
      line: "Text file \u00B7 dsregcmd.txt",
    },
    {
      name: "folder",
      source: { kind: "folder", path: "C:\\temp\\bundle" },
      line: "Evidence folder \u00B7 bundle",
    },
    { name: "clipboard", source: { kind: "clipboard" }, line: "Pasted text" },
    { name: "text", source: { kind: "text", label: "Manual" }, line: "Pasted text" },
  ] as const)("never shows a capture time for a $name source", ({ source, line }) => {
    // Even if a stray capturedAt reached a non-capture source, none is shown.
    seed({ source, displayLabel: "Source", capturedAt: CAPTURED_AT });
    render(<DsregcmdSidebar />);

    expect(screen.getByText(line)).toBeInTheDocument();
    expect(screen.queryByText(/Live capture/)).toBeNull();
    expect(screen.queryByText(formatDisplayDateTime(CAPTURED_AT) ?? "never")).toBeNull();
  });

  it("discloses paths only when a bundle or evidence path is set", () => {
    seed({ bundlePath: "C:\\bundle", evidenceFilePath: "C:\\bundle\\evidence\\dsregcmd.txt" });
    render(<DsregcmdSidebar />);

    expect(screen.getByText("Show paths")).toBeInTheDocument();
    expect(screen.getByText("C:\\bundle")).toBeInTheDocument();

    cleanup();
    seed({ bundlePath: null, evidenceFilePath: null });
    render(<DsregcmdSidebar />);
    expect(screen.queryByText("Show paths")).toBeNull();
  });

  it("sizes its text from the log list font size", () => {
    seed();
    useUiStore.setState({ logListFontSize: 18 });
    const { container } = render(<DsregcmdSidebar />);

    expect((container.firstElementChild as HTMLElement).style.fontSize).toBe("18px");
    useUiStore.setState({ logListFontSize: 13 });
  });
});

describe("DsregcmdSidebar on this page", () => {
  it("lists the sections as links in one Source and sections landmark", () => {
    const result = seed();
    render(<DsregcmdSidebar />);

    const nav = screen.getByRole("navigation", { name: "Source and sections" });
    expect(screen.getAllByRole("navigation")).toHaveLength(1);
    // The source card is inside the same landmark as the items.
    expect(within(nav).getByText("DSREGCMD")).toBeInTheDocument();
    const links = within(nav).getAllByRole("link");
    expect(links.map((link) => link.querySelector("span")?.textContent)).toEqual([
      "Overview",
      "Findings",
      "Facts",
      "Flows",
      "Timeline",
      "Event logs",
      "Export",
    ]);
    const findings = within(nav).getByRole("link", { name: /^Findings/ });
    expect(findings).toHaveAttribute("href", "#dsregcmd-section-findings");
    expect(findings).toHaveTextContent(`Findings${result.diagnostics.length}`);
    expect(within(nav).getByRole("link", { name: /^Event logs/ })).toHaveAttribute(
      "href",
      "#dsregcmd-section-event-logs",
    );
    expect(within(nav).getByRole("link", { name: "Overview" })).toHaveAttribute(
      "href",
      "#dsregcmd-section-overview",
    );
  });

  it("marks only the active section with aria-current=location", () => {
    seed();
    render(<DsregcmdSidebar />);

    expect(screen.getByRole("link", { name: "Overview" })).toHaveAttribute(
      "aria-current",
      "location",
    );
    expect(document.querySelectorAll('[aria-current="location"]')).toHaveLength(1);

    fireEvent.click(screen.getByRole("link", { name: /^Findings/ }));

    expect(useDsregcmdStore.getState().activeSection).toBe("findings");
    expect(useDsregcmdStore.getState().pendingScrollSection).toBe("findings");
    expect(screen.getByRole("link", { name: /^Findings/ })).toHaveAttribute(
      "aria-current",
      "location",
    );
    expect(screen.getByRole("link", { name: "Overview" })).not.toHaveAttribute("aria-current");
  });

  it("styles the active item with the sidebar selection pattern", () => {
    seed();
    render(<DsregcmdSidebar />);

    const active = screen.getByRole("link", { name: "Overview" });
    expect(active.style.borderLeft).toContain("3px solid");
    expect(active.style.borderLeft).toContain("colorCompoundBrandStroke");
    expect(active.style.backgroundColor).toContain("colorNeutralBackground1Selected");
    expect(active.style.color).toContain("colorBrandForeground1");
    expect(screen.getByRole("link", { name: /^Findings/ }).style.borderLeft).toContain("transparent");
  });

  it("counts the fact rows the page renders and respects Show not reported fields", () => {
    seed();
    render(
      <>
        <DsregcmdSidebar />
        <DsregcmdWorkspace />
      </>,
    );
    const factsCount = () =>
      Number(
        screen.getByRole("link", { name: /^Facts/ }).textContent?.replace(/\D/g, ""),
      );
    // FactsTable renders each visible row as a two-column grid.
    const renderedRows = () =>
      Array.from(
        document.querySelectorAll<HTMLElement>('[data-dsregcmd-section="facts"] div'),
      ).filter((element) => element.style.gridTemplateColumns.startsWith("170px")).length;
    const expectedRows = (show: boolean) => {
      const { factGroups } = renderHook(() => useDsregcmdDerived()).result.current;
      return factGroups.reduce(
        (total, group) => total + getVisibleFactRows(group, show).length,
        0,
      );
    };

    const hidden = factsCount();
    expect(hidden).toBe(renderedRows());
    expect(hidden).toBe(expectedRows(false));

    act(() => useDsregcmdStore.getState().setShowNotReported(true));
    const shown = factsCount();

    expect(shown).toBe(renderedRows());
    expect(shown).toBe(expectedRows(true));
    expect(shown).toBeGreaterThan(hidden);
  });

  it("Event logs switches to the event-log surface and Back returns to analysis", () => {
    seed();
    render(
      <>
        <DsregcmdSidebar />
        <DsregcmdWorkspace />
      </>,
    );

    fireEvent.click(screen.getByRole("link", { name: /^Event logs/ }));

    expect(useDsregcmdStore.getState().activeTab).toBe("event-logs");
    expect(screen.getByText("Channel:")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: /^Event logs/ })).toHaveAttribute(
      "aria-current",
      "location",
    );
    expect(screen.getByRole("link", { name: "Overview" })).not.toHaveAttribute("aria-current");

    fireEvent.click(screen.getByRole("button", { name: "Back to analysis" }));
    expect(useDsregcmdStore.getState().activeTab).toBe("analysis");
    expect(screen.queryByText("Channel:")).toBeNull();
  });

  it("another item leaves the event-log view and scrolls to its section", () => {
    const scrollIntoView = vi.fn();
    Element.prototype.scrollIntoView = scrollIntoView;
    seed();
    render(
      <>
        <DsregcmdSidebar />
        <DsregcmdWorkspace />
      </>,
    );
    fireEvent.click(screen.getByRole("link", { name: /^Event logs/ }));

    fireEvent.click(screen.getByRole("link", { name: /^Timeline/ }));

    expect(useDsregcmdStore.getState().activeTab).toBe("analysis");
    expect(scrollIntoView).toHaveBeenCalledTimes(1);
    expect(scrollIntoView.mock.contexts[0]).toBe(
      document.getElementById("dsregcmd-section-timeline"),
    );
    expect(useDsregcmdStore.getState().pendingScrollSection).toBeNull();
    delete (Element.prototype as { scrollIntoView?: unknown }).scrollIntoView;
  });

  it("disables Event logs accessibly when the source has no event log data", () => {
    seed({}, false);
    render(<DsregcmdSidebar />);

    const item = screen.getByRole("link", { name: /^Event logs/ });
    expect(item).toHaveAttribute("aria-disabled", "true");
    expect(item).toHaveAttribute("tabindex", "0");
    expect(item).not.toHaveAttribute("href");
    expect(item).toHaveAccessibleDescription(/no event log data/);
    expect(item.textContent).toBe("Event logs");
    fireEvent.click(item);
    expect(useDsregcmdStore.getState().activeTab).toBe("analysis");
  });

  it("renders the navigation disabled with No source loaded before any source", () => {
    render(<DsregcmdSidebar />);

    expect(screen.getByText("No source loaded")).toBeInTheDocument();
    const links = within(
      screen.getByRole("navigation", { name: "Source and sections" }),
    ).getAllByRole("link");
    expect(links).toHaveLength(7);
    for (const link of links) {
      expect(link).toHaveAttribute("aria-disabled", "true");
      expect(link).toHaveAccessibleDescription(/after a source has been analyzed/);
    }
    fireEvent.click(links[1]);
    expect(useDsregcmdStore.getState().pendingScrollSection).toBeNull();
  });

  it("renders the navigation disabled while analyzing", () => {
    useDsregcmdStore.getState().beginAnalysis({ kind: "file", path: "C:\\temp\\dsregcmd.txt" });
    render(<DsregcmdSidebar />);

    for (const link of screen.getAllByRole("link")) {
      expect(link).toHaveAttribute("aria-disabled", "true");
    }
  });

  it("shows no lines and chars while analyzing or after a failed load", () => {
    useDsregcmdStore.getState().beginAnalysis({ kind: "file", path: "C:\\temp\\dsregcmd.txt" });
    const { unmount } = render(<DsregcmdSidebar />);
    expect(screen.getByText("Text file \u00B7 dsregcmd.txt")).toBeInTheDocument();
    expect(screen.queryByText(/\d+ lines?/)).toBeNull();
    unmount();

    act(() => useDsregcmdStore.getState().failAnalysis("Access denied"));
    render(<DsregcmdSidebar />);
    expect(screen.getByText("Text file \u00B7 dsregcmd.txt")).toBeInTheDocument();
    expect(screen.queryByText(/\d+ lines?/)).toBeNull();
    expect(screen.queryByText(/\d+ chars?/)).toBeNull();
  });

  describe("Event logs count", () => {
    const withLiveQuery = (successful: number, failed: number, total: number) => {
      const result = analysisResult();
      result.eventLogAnalysis = {
        ...result.eventLogAnalysis!,
        totalEntryCount: total,
        liveQuery: {
          attemptedChannelCount: successful + failed,
          successfulChannelCount: successful,
          channelsWithResultsCount: total > 0 ? successful : 0,
          failedChannelCount: failed,
          perChannelEntryLimit: 500,
          channels: [],
        },
      };
      useDsregcmdStore
        .getState()
        .setResults("AzureAdJoined : YES", result, fixtureSourceContext());
    };

    it("shows no count when no live channel could be read", () => {
      withLiveQuery(0, 3, 0);
      render(<DsregcmdSidebar />);

      const item = screen.getByRole("link", { name: /^Event logs/ });
      expect(item.textContent).toBe("Event logs");
    });

    it("marks the count as a lower bound after a partial failure", () => {
      withLiveQuery(2, 1, 7);
      render(<DsregcmdSidebar />);

      const item = screen.getByRole("link", { name: /^Event logs/ });
      expect(item).toHaveTextContent("7+");
      expect(item).toHaveAccessibleName(/at least 7; some channels could not be read/);
    });

    it("shows the plain count when every channel was read, including zero", () => {
      withLiveQuery(3, 0, 0);
      render(<DsregcmdSidebar />);
      expect(screen.getByRole("link", { name: /^Event logs/ })).toHaveTextContent("Event logs0");

      cleanup();
      withLiveQuery(3, 0, 12);
      render(<DsregcmdSidebar />);
      expect(screen.getByRole("link", { name: /^Event logs/ })).toHaveTextContent("Event logs12");
    });

    it("shows the plain count for a non-live source", () => {
      const result = analysisResult();
      result.eventLogAnalysis = {
        ...result.eventLogAnalysis!,
        totalEntryCount: 5,
        liveQuery: null,
      };
      useDsregcmdStore
        .getState()
        .setResults("AzureAdJoined : YES", result, fixtureSourceContext());
      render(<DsregcmdSidebar />);

      expect(screen.getByRole("link", { name: /^Event logs/ })).toHaveTextContent("Event logs5");
    });
  });
});

describe("DsregcmdWorkspace scroll-spy", () => {
  type ObserverCallback = (entries: Partial<IntersectionObserverEntry>[]) => void;
  let callback: ObserverCallback | null = null;
  let observed: Element[] = [];

  beforeEach(() => {
    callback = null;
    observed = [];
    class FakeIntersectionObserver {
      constructor(cb: ObserverCallback) {
        callback = cb;
      }
      observe(element: Element) {
        observed.push(element);
      }
      unobserve() {}
      disconnect() {}
    }
    vi.stubGlobal("IntersectionObserver", FakeIntersectionObserver);
  });

  const section = (id: string) => document.getElementById(`dsregcmd-section-${id}`) as Element;

  it("observes every section and follows the first visible one", () => {
    seed();
    render(
      <>
        <DsregcmdSidebar />
        <DsregcmdWorkspace />
      </>,
    );

    expect(observed).toHaveLength(6);

    act(() => callback?.([{ target: section("facts"), isIntersecting: true }]));
    expect(useDsregcmdStore.getState().activeSection).toBe("facts");
    expect(screen.getByRole("link", { name: /^Facts/ })).toHaveAttribute("aria-current", "location");

    // Findings sits above Facts in the page, so it wins when both are visible.
    act(() => callback?.([{ target: section("findings"), isIntersecting: true }]));
    expect(useDsregcmdStore.getState().activeSection).toBe("findings");

    act(() => callback?.([{ target: section("findings"), isIntersecting: false }]));
    expect(useDsregcmdStore.getState().activeSection).toBe("facts");
  });

  it("does not observe while the event-log view is showing", () => {
    seed();
    useDsregcmdStore.getState().setActiveTab("event-logs");
    render(<DsregcmdWorkspace />);

    expect(observed).toHaveLength(0);
  });
  it("keeps the last section selected when the observer fires at the end of the range", () => {
    seed();
    render(
      <>
        <DsregcmdSidebar />
        <DsregcmdWorkspace />
      </>,
    );
    const container = section("overview").parentElement as HTMLElement;
    Object.defineProperties(container, {
      scrollTop: { value: 500, configurable: true },
      clientHeight: { value: 300, configurable: true },
      scrollHeight: { value: 800, configurable: true },
    });

    act(() => {
      container.dispatchEvent(new Event("scroll"));
    });
    expect(useDsregcmdStore.getState().activeSection).toBe("export");

    // A later observer callback must not overwrite the end-of-range choice.
    act(() => callback?.([{ target: section("flows"), isIntersecting: true }]));
    expect(useDsregcmdStore.getState().activeSection).toBe("export");
  });

  it("restores the analysis scroll position when returning from Event logs", () => {
    const offsets = new WeakMap<Element, number>();
    Object.defineProperty(HTMLElement.prototype, "scrollTop", {
      configurable: true,
      get() {
        return offsets.get(this) ?? 0;
      },
      set(value: number) {
        offsets.set(this, value);
      },
    });
    try {
      seed();
      render(
        <>
          <DsregcmdSidebar />
          <DsregcmdWorkspace />
        </>,
      );
      const container = section("overview").parentElement as HTMLElement;
      container.scrollTop = 420;
      act(() => {
        container.dispatchEvent(new Event("scroll"));
      });

      fireEvent.click(screen.getByRole("link", { name: /^Event logs/ }));
      expect(document.getElementById("dsregcmd-section-overview")).toBeNull();
      fireEvent.click(screen.getByRole("button", { name: "Back to analysis" }));

      const remounted = section("overview").parentElement as HTMLElement;
      expect(remounted).not.toBe(container);
      expect(remounted.scrollTop).toBe(420);
    } finally {
      delete (HTMLElement.prototype as { scrollTop?: unknown }).scrollTop;
    }
  });
});
