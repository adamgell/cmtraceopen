/** The session is read from the nearest provider, and reads as none without one. */
import { cleanup, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it } from "vitest";
import { EvtxAnalysisSessionProvider, useEvtxAnalysisSession } from "./evtx-analysis-session";

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
