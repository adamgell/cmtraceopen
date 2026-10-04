import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { useState } from "react";
import { WorkspaceErrorBoundary } from "./WorkspaceErrorBoundary";

function Boom({ message = "parser returned an unexpected shape" }: { message?: string }): never {
  throw new Error(message);
}

describe("WorkspaceErrorBoundary", () => {
  let consoleError: ReturnType<typeof vi.spyOn>;
  beforeEach(() => {
    // React logs a caught render error; that noise is not this test's subject.
    consoleError = vi.spyOn(console, "error").mockImplementation(() => {});
  });
  afterEach(() => consoleError.mockRestore());

  it("renders its children when nothing throws", () => {
    render(
      <WorkspaceErrorBoundary workspaceId="event-log">
        <div>timeline rows</div>
      </WorkspaceErrorBoundary>,
    );
    expect(screen.getByText("timeline rows")).toBeTruthy();
  });

  it("contains a throwing workspace instead of losing the tree", () => {
    render(
      <WorkspaceErrorBoundary workspaceId="sccm">
        <Boom />
      </WorkspaceErrorBoundary>,
    );
    const alert = screen.getByTestId("workspace-error-boundary");
    expect(alert.getAttribute("role")).toBe("alert");
    expect(alert.textContent).toContain("sccm");
    expect(alert.textContent).toContain("parser returned an unexpected shape");
  });

  it("retries a caught error only when the reset identity changes", () => {
    const initialSource = {};
    const { rerender } = render(
      <WorkspaceErrorBoundary workspaceId="log" resetKey={initialSource}>
        <Boom />
      </WorkspaceErrorBoundary>,
    );
    rerender(
      <WorkspaceErrorBoundary workspaceId="log" resetKey={initialSource}>
        <div>healthy source</div>
      </WorkspaceErrorBoundary>,
    );
    expect(screen.getByTestId("workspace-error-boundary")).toBeTruthy();

    rerender(
      <WorkspaceErrorBoundary workspaceId="log" resetKey={{}}>
        <Boom />
      </WorkspaceErrorBoundary>,
    );
    expect(screen.getByTestId("workspace-error-boundary")).toBeTruthy();

    rerender(
      <WorkspaceErrorBoundary workspaceId="log" resetKey={{}}>
        <div>healthy source</div>
      </WorkspaceErrorBoundary>,
    );
    expect(screen.queryByTestId("workspace-error-boundary")).toBeNull();
    expect(screen.getByText("healthy source")).toBeTruthy();
  });

  it("preserves healthy child state when the reset identity changes", () => {
    function Counter() {
      const [count, setCount] = useState(0);
      return <button onClick={() => setCount(count + 1)}>Count {count}</button>;
    }
    const { rerender } = render(
      <WorkspaceErrorBoundary workspaceId="log" resetKey={{}}>
        <Counter />
      </WorkspaceErrorBoundary>,
    );
    fireEvent.click(screen.getByText("Count 0"));
    rerender(
      <WorkspaceErrorBoundary workspaceId="log" resetKey={{}}>
        <Counter />
      </WorkspaceErrorBoundary>,
    );
    expect(screen.getByText("Count 1")).toBeTruthy();
  });

  it("clears the error when the boundary is remounted for another workspace", async () => {
    function Switcher() {
      const [id, setId] = useState("sccm");
      return (
        <>
          <button onClick={() => setId("event-log")}>switch</button>
          <WorkspaceErrorBoundary workspaceId={id} key={id}>
            {id === "sccm" ? <Boom /> : <div>timeline rows</div>}
          </WorkspaceErrorBoundary>
        </>
      );
    }
    render(<Switcher />);
    expect(screen.getByTestId("workspace-error-boundary")).toBeTruthy();

    fireEvent.click(screen.getByText("switch"));

    await waitFor(() =>
      expect(screen.queryByTestId("workspace-error-boundary")).toBeNull(),
    );
    expect(screen.getByText("timeline rows")).toBeTruthy();
  });
});
