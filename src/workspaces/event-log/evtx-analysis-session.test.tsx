/** The session is read from the nearest provider, and reads as none without one. */
import { cleanup, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it } from "vitest";
import dockSource from "./EvtxCorrelationDock.tsx?raw";
import modelSource from "./evtx-detail-context-model.ts?raw";
import {
  EvtxAnalysisSessionProvider,
  analysisSessionState,
  useEvtxAnalysisSession,
} from "./evtx-analysis-session";
import type { CorrelationStage } from "./useEvtxCorrelation";

afterEach(cleanup);

function Reader() {
  const session = useEvtxAnalysisSession();
  return <span data-testid="session">{session === null ? "none" : `${session.sessionId}:${session.revision}`}</span>;
}

describe("useEvtxAnalysisSession", () => {
  it("reads as no session outside a provider", () => {
    render(<Reader />);
    expect(screen.getByTestId("session")).toHaveTextContent("none");
  });

  it("reads the session the provider holds, and follows it", () => {
    const view = render(
      <EvtxAnalysisSessionProvider value={{ sessionId: "s", revision: 1 }}>
        <Reader />
      </EvtxAnalysisSessionProvider>,
    );
    expect(screen.getByTestId("session")).toHaveTextContent("s:1");
    view.rerender(
      <EvtxAnalysisSessionProvider value={{ sessionId: "s", revision: 2 }}>
        <Reader />
      </EvtxAnalysisSessionProvider>,
    );
    expect(screen.getByTestId("session")).toHaveTextContent("s:2");
    view.rerender(
      <EvtxAnalysisSessionProvider value={null}>
        <Reader />
      </EvtxAnalysisSessionProvider>,
    );
    expect(screen.getByTestId("session")).toHaveTextContent("none");
  });

  it("reads the nearest provider", () => {
    render(
      <EvtxAnalysisSessionProvider value={{ sessionId: "outer", revision: 1 }}>
        <EvtxAnalysisSessionProvider value={{ sessionId: "inner", revision: 7 }}>
          <Reader />
        </EvtxAnalysisSessionProvider>
      </EvtxAnalysisSessionProvider>,
    );
    expect(screen.getByTestId("session")).toHaveTextContent("inner:7");
  });
});

/**
 * No session is two states: one is on the way (the events are loaded and the analysis is being built
 * or rebuilt: the workspace holds the status at null for the whole build), and one is not coming.
 * Only the correlation stage tells them apart. The dock and the Details context list read the
 * answer from here, so they cannot disagree about it (#843).
 */
describe("analysisSessionState", () => {
  const STAGES: CorrelationStage[] = ["unavailable", "pending", "edgesOnly", "scanning", "ready"];
  const session = { sessionId: "s", revision: 1 };

  it("is available whenever there is a session, whatever the stage", () => {
    for (const stage of STAGES) expect(analysisSessionState(session, stage), stage).toBe("available");
  });

  it("is building with no session while the stage is pending", () => {
    expect(analysisSessionState(null, "pending")).toBe("building");
  });

  it("is none with no session in every other stage", () => {
    for (const stage of STAGES.filter((candidate) => candidate !== "pending")) {
      expect(analysisSessionState(null, stage), stage).toBe("none");
    }
  });

  it("is the one place that spells the rule: neither the dock nor the Details model reads the stage itself", () => {
    expect(dockSource).toContain("analysisSessionState(");
    expect(dockSource).not.toMatch(/stage\s*===\s*"pending"/);
    expect(modelSource).not.toMatch(/"pending"|stage/);
  });
});
