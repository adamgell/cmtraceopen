import { describe, expect, it } from "vitest";
import {
  EVTX_LOCAL_MACHINE_NAME,
  eventLogMachineName,
  eventLogSourceLabel,
} from "./evtx-source-label";

const on = (...computers: string[]) => computers.map((computer) => ({ computer }));

describe("eventLogMachineName", () => {
  it("prefers the remote machine over what the records say", () => {
    expect(eventLogMachineName({ remoteMachine: "SERVER01", records: on("PC-A", "PC-A") })).toBe("SERVER01");
  });

  it("otherwise takes the computer most of the records carry", () => {
    expect(eventLogMachineName({ remoteMachine: null, records: on("PC-A", "PC-B", "PC-B", "PC-B", "PC-A") })).toBe("PC-B");
  });

  it("lets the first one seen win a tie, so the name does not change as records merge in", () => {
    expect(eventLogMachineName({ remoteMachine: null, records: on("PC-B", "PC-A", "PC-A", "PC-B") })).toBe("PC-B");
  });

  it("ignores blank computers and trims the rest", () => {
    expect(eventLogMachineName({ remoteMachine: null, records: on("", "  ", " PC-A ", "PC-A", "") })).toBe("PC-A");
    expect(eventLogMachineName({ remoteMachine: "  ", records: on("PC-A") })).toBe("PC-A");
  });

  it("says This computer when nothing names a machine, and never invents one", () => {
    expect(eventLogMachineName({ remoteMachine: null, records: [] })).toBe(EVTX_LOCAL_MACHINE_NAME);
    expect(eventLogMachineName({ remoteMachine: null, records: on("", " ") })).toBe("This computer");
  });
});

describe("eventLogSourceLabel", () => {
  it("reads Source: machine, then the mode", () => {
    expect(eventLogSourceLabel({ sourceMode: "live", remoteMachine: null, records: on("PC-A") })).toBe("Source: PC-A · live");
    expect(eventLogSourceLabel({ sourceMode: "files", remoteMachine: null, records: on("PC-A") })).toBe("Source: PC-A · files");
    expect(eventLogSourceLabel({ sourceMode: "live", remoteMachine: "SERVER01", records: [] })).toBe("Source: SERVER01 · live");
  });

  it("has no label while no source is open", () => {
    expect(eventLogSourceLabel({ sourceMode: null, remoteMachine: null, records: on("PC-A") })).toBeNull();
  });
});
