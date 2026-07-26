import { describe, expect, it } from "vitest";
import {
  buildEspGraphNameMap,
  lookupEspGraphName,
  resolveEspIdentifiers,
} from "./esp-graph-names";
import {
  makeEspAppsSection,
  makeEspGraphApp,
  makeEspGraphOverlay,
  makeEspSnapshot,
  makeEspWorkload,
} from "./esp-session-fixtures";

const AUTOPATCH = "Win32App_18c617f8-26d2-40d5-9e0f-fc1015e5da79_1";

describe("buildEspGraphNameMap", () => {
  it("resolves a known workload's decorated identifier to its name", () => {
    const snapshot = makeEspSnapshot({
      workloads: [
        makeEspWorkload({
          rawIdentifier: AUTOPATCH,
          displayName: "Windows Autopatch Client Broker",
        }),
      ],
    });
    const names = buildEspGraphNameMap(snapshot);
    expect(lookupEspGraphName(names, AUTOPATCH)).toBe(
      "Windows Autopatch Client Broker",
    );
    expect(resolveEspIdentifiers(AUTOPATCH, names)).toBe(
      "Windows Autopatch Client Broker",
    );
  });

  it("prefers the Graph name over the local workload name", () => {
    const guid = "a7c420db-0fa1-4c26-aca5-467e1a4dee73";
    const snapshot = makeEspSnapshot({
      workloads: [
        makeEspWorkload({
          rawIdentifier: `Win32App_${guid}_1`,
          displayName: "Local name",
        }),
      ],
      graph: makeEspGraphOverlay({
        apps: makeEspAppsSection([
          makeEspGraphApp({ appId: guid, displayName: "Graph name" }),
        ]),
      }),
    });
    const names = buildEspGraphNameMap(snapshot);
    expect(resolveEspIdentifiers(`Win32App_${guid}_1`, names)).toBe(
      "Graph name",
    );
  });

  it("leaves unknown (non-workload) identifiers untouched", () => {
    const names = buildEspGraphNameMap(makeEspSnapshot());
    const setupLine = "Reconstruct OS {04A446E2-4ADE-42DC-810B-EA70CE70CF11}";
    expect(resolveEspIdentifiers(setupLine, names)).toContain(
      "{04A446E2-4ADE-42DC-810B-EA70CE70CF11}",
    );
  });
});
