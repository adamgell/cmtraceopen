/**
 * The Event Logs source pill (spec 8.1): copy for every source and tail state, the machine-name
 * fallback chain, and Adam's rendering criterion for the `liveSource` token (issue #847): the
 * pill is drawn from that token alone, and its label, dot, fill and border are measured as
 * rendered in all seven themes.
 */
import { act, cleanup, render, screen } from "@testing-library/react";
import { tokens } from "@fluentui/react-components";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("@tauri-apps/api/event", () => ({
  listen: vi.fn(async () => () => undefined),
}));

import { WorkspaceToolbarAction } from "../../components/layout/Toolbar";
import { contrastRatio } from "../../lib/color-contrast";
import { getAllThemes, type ThemeId } from "../../lib/themes";
import type { CMTraceTheme } from "../../lib/themes/types";
import { useUiStore } from "../../stores/ui-store";
import {
  EvtxToolbarAction,
  LOCAL_MACHINE_LABEL,
  filesLabel,
  liveDescription,
  liveLabel,
  liveTailStateFor,
  mostFrequentComputer,
  resolveMachineName,
} from "./EvtxToolbarAction";
import { useEvtxStore } from "./evtx-store";
import { buildEvtxVisualTokens, resolveToken } from "./evtx-visual-tokens";
import { eventLogWorkspace } from "./index";
import type { EvtxLevel, EvtxLiveMode, EvtxRecord } from "./types";
import toolbarActionSource from "./EvtxToolbarAction.tsx?raw";

let nextRecordId = 0;

/** Placeholder machine names only; no real host appears in a fixture. */
function record(computer: string, level: EvtxLevel = "Information"): EvtxRecord {
  nextRecordId += 1;
  return {
    id: nextRecordId,
    eventRecordId: nextRecordId,
    timestamp: "2026-10-10T12:00:00.000Z",
    timestampEpoch: Date.UTC(2026, 9, 10, 12, 0, nextRecordId),
    provider: "Contoso-Provider",
    channel: "System",
    eventId: 7036,
    level,
    computer,
    message: `event ${nextRecordId}`,
    eventData: [],
    rawXml: "",
    sourceLabel: "Live",
  };
}

function resetStores() {
  useUiStore.setState(useUiStore.getInitialState(), true);
  useEvtxStore.getState().reset();
}

function loadLive(
  options: {
    remoteMachine?: string | null;
    records?: EvtxRecord[];
    tailMode?: EvtxLiveMode | null;
    /** Channels whose load completed. */
    loadedChannels?: string[];
    /** Channels whose tail is active; defaults to every loaded channel when a tail is running. */
    tailChannels?: string[];
  } = {},
) {
  const loadedChannels = options.loadedChannels ?? ["System"];
  const tailMode = options.tailMode ?? null;
  useEvtxStore.setState({
    sourceMode: "live",
    remoteMachine: options.remoteMachine ?? null,
    records: options.records ?? [record("CONTOSO-PC01")],
    loadedChannels: new Set(loadedChannels),
    tailMode,
    tailChannels: new Set(
      options.tailChannels ??
        (tailMode === null || tailMode === "unsupported" ? [] : loadedChannels),
    ),
  });
}

function loadFiles(sourceCount: number) {
  useEvtxStore.setState({
    sourceMode: "files",
    sourcePaths: Array.from({ length: sourceCount }, (_, i) => `C:\\Evidence\\log${i}.evtx`),
    records: [record("CONTOSO-PC01")],
  });
}

const pill = () => screen.getByTestId("evtx-source-pill");
const label = () => screen.getByTestId("evtx-source-pill-label");
const dot = () => screen.getByTestId("evtx-source-pill-dot");

describe("EvtxToolbarAction copy", () => {
  beforeEach(resetStores);
  afterEach(cleanup);

  it("is the Event Logs workspace toolbar action", async () => {
    loadFiles(2);
    render(<WorkspaceToolbarAction workspace={eventLogWorkspace} />);

    expect(await screen.findByTestId("evtx-source-pill")).toHaveTextContent("Files · 2 sources");
  });

  it("renders nothing until a source is loaded", () => {
    const { container } = render(<EvtxToolbarAction />);
    expect(container).toBeEmptyDOMElement();
  });

  describe("live source", () => {
    it("names the remote machine", () => {
      loadLive({ remoteMachine: "CONTOSO-SRV01", records: [record("CONTOSO-PC01")] });
      render(<EvtxToolbarAction />);

      expect(label()).toHaveTextContent("Live · CONTOSO-SRV01");
      expect(pill()).toHaveAttribute("data-source", "live");
    });

    it("falls back to the most frequent computer in the loaded events", () => {
      loadLive({
        records: [record("CONTOSO-PC02"), record("CONTOSO-PC01"), record("CONTOSO-PC01")],
      });
      render(<EvtxToolbarAction />);

      expect(label()).toHaveTextContent("Live · CONTOSO-PC01");
    });

    it("says This computer when no event names a machine", () => {
      loadLive({ records: [record(""), record("   ")] });
      render(<EvtxToolbarAction />);

      expect(label()).toHaveTextContent(`Live · ${LOCAL_MACHINE_LABEL}`);
    });

    it("ignores a blank remote machine", () => {
      loadLive({ remoteMachine: "  ", records: [record("CONTOSO-PC01")] });
      render(<EvtxToolbarAction />);

      expect(label()).toHaveTextContent("Live · CONTOSO-PC01");
    });

    it.each<[EvtxLiveMode | null, string]>([
      [null, "Live · CONTOSO-PC01"],
      ["subscription", "Live · CONTOSO-PC01 · tailing"],
      ["polling", "Live · CONTOSO-PC01 · polling"],
      ["mixed", "Live · CONTOSO-PC01 · tailing"],
      ["unsupported", "Live · CONTOSO-PC01 · not tailing"],
    ])("reads the %s tail state, with every loaded channel followed, as %s", (tailMode, expected) => {
      loadLive({ tailMode });
      render(<EvtxToolbarAction />);

      expect(label().textContent).toBe(expected);
    });

    it("names the machine on an unsupported tail, so a remote source is never mistaken for this computer", () => {
      loadLive({ remoteMachine: "CONTOSO-SRV01", tailMode: "unsupported" });
      render(<EvtxToolbarAction />);

      expect(label().textContent).toBe("Live · CONTOSO-SRV01 · not tailing");
    });

    it("follows the tail state as it changes", () => {
      loadLive({ tailMode: "subscription" });
      render(<EvtxToolbarAction />);
      expect(label().textContent).toBe("Live · CONTOSO-PC01 · tailing");

      act(() => useEvtxStore.setState({ tailMode: "unsupported", tailChannels: new Set() }));
      expect(label().textContent).toBe("Live · CONTOSO-PC01 · not tailing");
    });

    describe("a tail that follows only some of the loaded channels", () => {
      // The store reports "mixed" for any two distinct per-channel modes, and a channel whose
      // tail failed to start is recorded as "unsupported". So "mixed" also covers subscriptions
      // beside a channel that is not followed at all, where nothing polls.
      const four = ["Application", "Security", "Setup", "System"];

      it.each<[string, EvtxLiveMode]>([
        ["subscription plus unsupported", "mixed"],
        ["polling plus unsupported", "mixed"],
      ])("reads %s as 3 of 4 channels, and never claims polling or a mix", (_name, tailMode) => {
        loadLive({
          tailMode,
          loadedChannels: four,
          tailChannels: ["Application", "Setup", "System"],
        });
        render(<EvtxToolbarAction />);

        expect(label().textContent).toBe("Live · CONTOSO-PC01 · tailing 3 of 4 channels");
        expect(pill().getAttribute("title")).toBe(
          "Live event logs from CONTOSO-PC01. Live tail is following 3 of 4 channels. Not followed: Security.",
        );
        expect(pill().getAttribute("title")).not.toMatch(/poll|mixed|subscription/i);
        expect(label().textContent).not.toMatch(/poll|mixed/i);
      });

      it("names every channel that is not followed, sorted", () => {
        loadLive({
          tailMode: "mixed",
          loadedChannels: four,
          tailChannels: ["System"],
        });
        render(<EvtxToolbarAction />);

        expect(label().textContent).toBe("Live · CONTOSO-PC01 · tailing 1 of 4 channels");
        expect(pill().getAttribute("title")).toMatch(
          /Not followed: Application, Security, Setup\.$/,
        );
      });

      it("caps a long list of channels that are not followed", () => {
        const many = Array.from({ length: 14 }, (_, i) => `Channel${String(i).padStart(2, "0")}`);
        loadLive({ tailMode: "mixed", loadedChannels: many, tailChannels: ["Channel00"] });
        render(<EvtxToolbarAction />);

        const title = pill().getAttribute("title") ?? "";
        expect(title).toContain("Channel01");
        expect(title).toContain("Channel10");
        expect(title).not.toContain("Channel11");
        expect(title).toMatch(/and 3 more\.$/);
      });

      it("reads a tail that follows no loaded channel as not tailing", () => {
        loadLive({ tailMode: "mixed", loadedChannels: four, tailChannels: [] });
        render(<EvtxToolbarAction />);

        expect(label().textContent).toBe("Live · CONTOSO-PC01 · not tailing");
        expect(pill().getAttribute("title")).toMatch(/not following any loaded channel/);
      });

      it("claims no specific mode for a mixed tail even when every loaded channel is followed", () => {
        // The aggregate is computed once at tail start and kept when a channel is cleared, so a
        // "mixed" can outlive the mix: nothing here may say subscriptions or polling.
        loadLive({ tailMode: "mixed", loadedChannels: four, tailChannels: four });
        render(<EvtxToolbarAction />);

        expect(label().textContent).toBe("Live · CONTOSO-PC01 · tailing");
        expect(pill().getAttribute("title")).toBe(
          "Live event logs from CONTOSO-PC01. Live tail is running.",
        );
        expect(pill().getAttribute("title")).not.toMatch(/poll|subscription|mixed/i);
        expect(label().textContent).not.toMatch(/poll|subscription|mixed/i);
      });

      describe("after a channel is cleared during a mixed tail", () => {
        // clearChannel drops the channel from loadedChannels and tailChannels but keeps the old
        // aggregate "mixed" while any tail channel remains.
        it("makes no polling claim when the unfollowed channel is cleared (subscription plus unsupported)", () => {
          loadLive({
            tailMode: "mixed",
            loadedChannels: four,
            tailChannels: ["Application", "Setup", "System"],
          });
          render(<EvtxToolbarAction />);
          expect(label().textContent).toBe("Live · CONTOSO-PC01 · tailing 3 of 4 channels");

          // Security, whose tail failed to start, is cleared: 3 of 3 are followed, none polls.
          act(() =>
            useEvtxStore.setState({ loadedChannels: new Set(["Application", "Setup", "System"]) }),
          );

          expect(label().textContent).toBe("Live · CONTOSO-PC01 · tailing");
          expect(pill().getAttribute("title")).not.toMatch(/poll|subscription|mixed/i);
        });

        it("makes no mixed claim when the polled channel is cleared (a real mix that became uniform)", () => {
          loadLive({ tailMode: "mixed", loadedChannels: four, tailChannels: four });
          render(<EvtxToolbarAction />);

          // The one polled channel is cleared; the remaining three subscribe.
          act(() =>
            useEvtxStore.setState({
              loadedChannels: new Set(["Application", "Security", "Setup"]),
              tailChannels: new Set(["Application", "Security", "Setup"]),
            }),
          );

          expect(label().textContent).toBe("Live · CONTOSO-PC01 · tailing");
          expect(pill().getAttribute("title")).toBe(
            "Live event logs from CONTOSO-PC01. Live tail is running.",
          );
        });
      });

      it("counts a channel loaded after the tail started as not followed", () => {
        loadLive({ tailMode: "subscription", loadedChannels: ["System"], tailChannels: ["System"] });
        render(<EvtxToolbarAction />);
        expect(label().textContent).toBe("Live · CONTOSO-PC01 · tailing");

        act(() =>
          useEvtxStore.setState({ loadedChannels: new Set(["System", "Application"]) }),
        );
        expect(label().textContent).toBe("Live · CONTOSO-PC01 · tailing 1 of 2 channels");
      });

      it("ignores tail channels that are no longer loaded", () => {
        const state = liveTailStateFor({
          tailMode: "subscription",
          tailChannels: new Set(["System", "Cleared"]),
          loadedChannels: new Set(["System"]),
        });
        expect(state).toEqual({ mode: "subscription", followed: 1, loaded: 1, notFollowed: [] });
      });
    });

    it("keeps the machine name in the description of an unsupported tail", () => {
      loadLive({ tailMode: "unsupported" });
      render(<EvtxToolbarAction />);

      expect(pill().getAttribute("title")).toBe(
        "Live event logs from CONTOSO-PC01. Live tail is not supported for these channels, so new events are not followed.",
      );
    });

    it.each<[EvtxLiveMode | null, RegExp]>([
      [null, /Live tail is not running\./],
      ["subscription", /running on event subscriptions/],
      ["polling", /running by polling/],
      ["mixed", /^Live event logs from CONTOSO-PC01\. Live tail is running\.$/],
      ["unsupported", /not supported/],
    ])("describes the %s tail state in the title", (tailMode, expected) => {
      loadLive({ tailMode });
      render(<EvtxToolbarAction />);

      expect(pill().getAttribute("title")).toMatch(expected);
    });
  });

  describe("files source", () => {
    it("counts the opened sources", () => {
      loadFiles(3);
      render(<EvtxToolbarAction />);

      expect(label().textContent).toBe("Files · 3 sources");
      expect(pill()).toHaveAttribute("data-source", "files");
    });

    it("uses the singular for one source", () => {
      loadFiles(1);
      render(<EvtxToolbarAction />);

      expect(label().textContent).toBe("Files · 1 source");
    });

    it("prints no number when no source is on record", () => {
      loadFiles(0);
      render(<EvtxToolbarAction />);

      expect(label().textContent).toBe("Files");
    });

    it("draws the count in the numeric font and shows no machine name", () => {
      loadFiles(4);
      render(<EvtxToolbarAction />);

      const count = label().querySelector("span");
      expect(count?.textContent).toBe("4");
      expect(count?.style.fontFamily).toBe(tokens.fontFamilyNumeric);
      expect(count?.style.fontVariantNumeric).toBe("tabular-nums");
      expect(pill()).not.toHaveTextContent("CONTOSO-PC01");
    });
  });

  describe("shape", () => {
    it("draws a 7 px dot that assistive technology skips", () => {
      loadLive();
      render(<EvtxToolbarAction />);

      expect(dot()).toHaveAttribute("aria-hidden", "true");
      expect(dot().style.width).toBe("7px");
      expect(dot().style.height).toBe("7px");
      expect(dot().style.borderRadius).toBe("50%");
    });

    it("uses radius 8, padding 3px 10px and weight 600 (spec 8.1 and D21)", () => {
      loadLive();
      render(<EvtxToolbarAction />);

      expect(pill().style.borderRadius).toBe("8px");
      expect(pill().style.padding).toBe("3px 10px");
      expect(pill().style.fontWeight).toBe("600");
    });

    it.each([
      [13, "11px"],
      [16, "14px"],
      [20, "18px"],
      // The smallest log font size is 11, which would give 9: the pill keeps a 10 px floor.
      [11, "10px"],
    ])("sizes the text two steps under the log font size (%i gives %s)", (size, expected) => {
      useUiStore.setState({ logListFontSize: size });
      loadLive();
      render(<EvtxToolbarAction />);

      expect(pill().style.fontSize).toBe(expected);
    });

    it("is a status, not a control: nothing in it takes focus or a click", () => {
      loadLive();
      const { container } = render(<EvtxToolbarAction />);

      expect(screen.queryByRole("button")).toBeNull();
      expect(screen.queryByRole("link")).toBeNull();
      expect(container.querySelectorAll("[tabindex], button, a, input")).toHaveLength(0);
      // No class means no :hover or :focus rule can exist for it, so the colors measured below
      // are the only ones it ever draws.
      expect(pill().className).toBe("");
      expect(label().className).toBe("");
      expect(dot().className).toBe("");
    });
  });
});

describe("EvtxToolbarAction helpers", () => {
  it("picks the most frequent computer, and the name that sorts first on a tie", () => {
    expect(
      mostFrequentComputer([
        { computer: "CONTOSO-PC02" },
        { computer: "CONTOSO-PC01" },
        { computer: "CONTOSO-PC02" },
      ]),
    ).toBe("CONTOSO-PC02");
    expect(
      mostFrequentComputer([{ computer: "CONTOSO-PC02" }, { computer: "CONTOSO-PC01" }]),
    ).toBe("CONTOSO-PC01");
    expect(
      mostFrequentComputer([{ computer: "CONTOSO-PC01" }, { computer: "CONTOSO-PC02" }]),
    ).toBe("CONTOSO-PC01");
  });

  it("returns null when no event names a computer", () => {
    expect(mostFrequentComputer([])).toBeNull();
    expect(mostFrequentComputer([{ computer: "" }, { computer: " " }])).toBeNull();
  });

  it("prefers the remote machine over anything the events say", () => {
    expect(resolveMachineName("CONTOSO-SRV01", [{ computer: "CONTOSO-PC01" }])).toBe(
      "CONTOSO-SRV01",
    );
    expect(resolveMachineName(null, [{ computer: "CONTOSO-PC01" }])).toBe("CONTOSO-PC01");
    expect(resolveMachineName(null, [])).toBe(LOCAL_MACHINE_LABEL);
  });

  it("builds the labels", () => {
    const state = (tailMode: EvtxLiveMode | null) =>
      liveTailStateFor({
        tailMode,
        tailChannels: new Set(),
        loadedChannels: new Set(),
      });
    expect(liveLabel("CONTOSO-PC01", state("unsupported"))).toBe("Live · CONTOSO-PC01 · not tailing");
    expect(filesLabel(5)).toBe("Files · 5 sources");
    expect(liveDescription("CONTOSO-PC01", state(null))).toContain("CONTOSO-PC01");
  });
});

// ---- Adam's criterion on the `liveSource` token (issue #847) ---------------------------------

const SEVEN_THEMES: ThemeId[] = [
  "light",
  "dark",
  "high-contrast",
  "classic-cmtrace",
  "solarized-dark",
  "nord",
  "dracula",
];

/** Opaque `#rrggbb` for a color the pill rendered: a `var()` token, an `rgb()` value or a hex. */
function opaqueHex(value: string, theme: CMTraceTheme): string {
  const trimmed = value.trim();
  expect(trimmed, "a color the test can measure").not.toBe("");
  if (trimmed.startsWith("var(")) return resolveToken(trimmed, theme).toLowerCase();
  const rgb = /^rgb\(\s*(\d+),\s*(\d+),\s*(\d+)\s*\)$/.exec(trimmed);
  if (rgb) {
    return `#${[rgb[1], rgb[2], rgb[3]]
      .map((channel) => Number(channel).toString(16).padStart(2, "0"))
      .join("")}`;
  }
  expect(trimmed, "a hex color").toMatch(/^#[0-9a-f]{6}$/i);
  return trimmed.toLowerCase();
}

/** The color a descendant inherits: the nearest inline `color` on it or an ancestor. */
function inheritedColor(element: HTMLElement): string {
  for (let node: HTMLElement | null = element; node; node = node.parentElement) {
    if (node.style.color !== "") return node.style.color;
  }
  throw new Error("no inline color on the element or any ancestor");
}

function borderColor(element: HTMLElement): string {
  const match = /^\S+\s+solid\s+(.+)$/.exec(element.style.border);
  if (!match) throw new Error(`unexpected border declaration: "${element.style.border}"`);
  return match[1];
}

function themeById(id: string): CMTraceTheme {
  const theme = getAllThemes().find((candidate) => candidate.id === id);
  if (!theme) throw new Error(`Unknown theme ${id}`);
  return theme;
}

describe("liveSource token as rendered by the pill", () => {
  beforeEach(resetStores);
  afterEach(cleanup);

  it("covers all seven themes", () => {
    expect(
      getAllThemes()
        .map((theme) => theme.id)
        .sort(),
    ).toEqual([...SEVEN_THEMES].sort());
  });

  describe.each(SEVEN_THEMES)("in the %s theme", (themeId) => {
    const theme = themeById(themeId);
    const { liveSource } = buildEvtxVisualTokens(theme);

    function renderLive() {
      useUiStore.setState({ themeId });
      loadLive({ tailMode: "subscription" });
      render(<EvtxToolbarAction />);
    }

    it("draws the fill, border, label and dot from liveSource and nothing else", () => {
      renderLive();

      expect(pill().style.backgroundColor).toBe(liveSource.background);
      expect(borderColor(pill())).toBe(liveSource.border);
      expect(opaqueHex(inheritedColor(label()), theme)).toBe(
        opaqueHex(liveSource.foreground, theme),
      );
      expect(opaqueHex(dot().style.backgroundColor, theme)).toBe(
        opaqueHex(liveSource.foreground, theme),
      );
    });

    it("keeps the label at 4.5:1 on the pill fill", () => {
      renderLive();

      const fill = opaqueHex(pill().style.backgroundColor, theme);
      const ratio = contrastRatio(opaqueHex(inheritedColor(label()), theme), fill);
      expect(
        ratio,
        `${themeId}: label ${inheritedColor(label())} on fill ${fill} is ${ratio.toFixed(2)}:1`,
      ).toBeGreaterThanOrEqual(4.5);
    });

    it("keeps the 7 px dot at 3:1 on the pill fill", () => {
      renderLive();

      const fill = opaqueHex(pill().style.backgroundColor, theme);
      const dotColor = opaqueHex(dot().style.backgroundColor, theme);
      const ratio = contrastRatio(dotColor, fill);
      expect(
        ratio,
        `${themeId}: dot ${dotColor} on fill ${fill} is ${ratio.toFixed(2)}:1`,
      ).toBeGreaterThanOrEqual(3);
    });

    it("has no hover or focus state whose colors could differ", () => {
      renderLive();

      for (const element of [pill(), label(), dot()]) {
        expect(element.className).toBe("");
        expect(element.getAttribute("tabindex")).toBeNull();
      }
    });

    it("names the state in text, because neither the fill nor the border can", () => {
      renderLive();

      // The fill is pale green on the toolbar's neutral surface and the border is Phase 1's
      // decorative token, exempt in its inventory (INVENTORY_EXEMPTIONS). Measured in Phase 1,
      // the fill separates from the toolbar by only 1.00 to 1.64:1 across these seven themes, so
      // Adam's criterion that the border not be relied on to identify the pill is met by the
      // label: the state is spelled out and the dot is decoration. No ratio is asserted for the
      // fill or the border, so retuning that token is not a failure here.
      expect(label().textContent).toMatch(/^Live · /);
      expect(dot()).toHaveAttribute("aria-hidden", "true");
    });

    it("keeps the files pill's label at 4.5:1 and its dot at 3:1 on its own fill", () => {
      useUiStore.setState({ themeId });
      loadFiles(2);
      render(<EvtxToolbarAction />);

      const fill = opaqueHex(pill().style.backgroundColor, theme);
      expect(fill).toBe(resolveToken(tokens.colorNeutralBackground3, theme).toLowerCase());
      const text = opaqueHex(inheritedColor(label()), theme);
      expect(contrastRatio(text, fill), `${themeId}: files label ${text} on ${fill}`).toBeGreaterThanOrEqual(4.5);
      const files = opaqueHex(dot().style.backgroundColor, theme);
      expect(contrastRatio(files, fill), `${themeId}: files dot ${files} on ${fill}`).toBeGreaterThanOrEqual(3);
      expect(opaqueHex(borderColor(pill()), theme)).toBe(
        resolveToken(tokens.colorNeutralStroke1, theme).toLowerCase(),
      );
    });
  });

  it("holds the live label 20 dE00 from every level mark by drawing exactly liveSource.foreground", () => {
    // Phase 1 (FAMILY_SEPARATION) enforces the distance on the token. The pill draws that token
    // unchanged and sits beside no level mark, so the distance carries over; this pins the
    // identity that makes it so.
    for (const theme of getAllThemes()) {
      useUiStore.setState({ themeId: theme.id });
      loadLive();
      const { unmount } = render(<EvtxToolbarAction />);
      expect(opaqueHex(inheritedColor(label()), theme)).toBe(
        opaqueHex(theme.severityPalette.eventLog.live, theme),
      );
      unmount();
    }
  });

  it("names no palette, severity palette or color literal in its source", () => {
    const code = toolbarActionSource
      .replace(/\/\*[\s\S]*?\*\//g, "")
      .replace(/(^|[^:])\/\/.*$/gm, "$1");

    expect(code).toContain("visual.liveSource");
    expect(code).not.toMatch(/colorPalette/);
    expect(code).not.toMatch(/severityPalette|mergeColors|eventLog\./);
    expect(code).not.toMatch(/#[0-9a-f]{3,8}\b/i);
    expect(code).not.toMatch(/\b(rgba?|hsla?|oklch|oklab|lab|lch|hwb|color-mix)\(/i);
    expect(code).not.toMatch(/["'`](black|white|red|green|blue|yellow|orange|purple|gray|grey)["'`]/i);
  });
});
