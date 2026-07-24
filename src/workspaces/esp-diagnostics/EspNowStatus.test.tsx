import { render } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { deriveEspCurrentTask } from "./esp-current-task";
import { EspNowStatus } from "./EspNowStatus";
import { makeEspSession, makeEspWorkload } from "./esp-session-fixtures";
import type { EspWorkload } from "./types";

const sessions = [makeEspSession({ sessionId: "session-1", isLatest: true })];

function installing(
  displayName: string | null,
  overrides: Partial<EspWorkload> = {},
): EspWorkload {
  return makeEspWorkload({
    sessionId: "session-1",
    status: {
      raw: "installing",
      normalized: "installing",
      display: "Installing",
      detail: null,
    },
    displayName,
    ...overrides,
  });
}

describe("EspNowStatus", () => {
  it("shows the actively installing workload as the live current task", () => {
    const workloads: EspWorkload[] = [
      installing("Contoso VPN", {
        workloadId: "a",
        rawIdentifier: "Win32App_11111111-1111-4111-8111-111111111111_1",
      }),
      makeEspWorkload({
        workloadId: "b",
        sessionId: "session-1",
        status: {
          raw: "succeeded",
          normalized: "succeeded",
          display: "Installed",
          detail: null,
        },
      }),
      makeEspWorkload({
        workloadId: "c",
        sessionId: "session-1",
        status: {
          raw: "notInstalled",
          normalized: "notInstalled",
          display: "Waiting",
          detail: null,
        },
      }),
    ];
    const task = deriveEspCurrentTask(workloads, sessions, "deviceSetup");
    expect(task.state).toBe("running");

    const { container } = render(
      <EspNowStatus
        task={task}
        phase="deviceSetup"
        graphNames={new Map()}
        isLive
      />,
    );
    const text = container.textContent ?? "";
    expect(text).toContain("Contoso VPN");
    expect(text).toContain("INSTALLING");
    expect(text).toContain("Device setup");
    expect(text).toContain("Live");
    expect(text).toContain("3 tracked");
    expect(text).toContain("running");
    expect(text).toContain("queued");
  });

  it("resolves the task name from Graph when the workload has no local name", () => {
    const workloads = [
      installing(null, {
        workloadId: "a",
        rawIdentifier: "Win32App_a7c420db-0fa1-4c26-aca5-467e1a4dee73_1",
      }),
    ];
    const task = deriveEspCurrentTask(workloads, sessions, "deviceSetup");
    const graphNames = new Map([
      ["a7c420db-0fa1-4c26-aca5-467e1a4dee73", "Company Portal"],
    ]);

    const { container } = render(
      <EspNowStatus
        task={task}
        phase="deviceSetup"
        graphNames={graphNames}
        isLive
      />,
    );
    expect(container.textContent).toContain("Company Portal");
  });

  it("labels a replayed capture as captured, not live", () => {
    const task = deriveEspCurrentTask([], sessions, "completed");
    const { container } = render(
      <EspNowStatus
        task={task}
        phase="completed"
        graphNames={new Map()}
        isLive={false}
      />,
    );
    const text = container.textContent ?? "";
    expect(text).toContain("Captured");
    expect(text).toContain("Enrollment complete");
    expect(text).not.toContain("Live ·");
  });
});
