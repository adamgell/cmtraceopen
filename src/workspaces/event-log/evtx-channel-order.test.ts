import { describe, expect, it } from "vitest";
import {
  buildChannelTree,
  isTextLogChannel,
  orderChannelNames,
  textLogChannelNames,
} from "./evtx-channel-order";

describe("orderChannelNames", () => {
  const names = [
    "Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider/Admin",
    "System",
    "Microsoft-Windows-AAD/Operational",
    "Application",
    "Security",
    "Setup",
  ];

  it("puts Windows Logs first in Event Viewer order, then the sorted service tree", () => {
    expect(orderChannelNames(names)).toEqual([
      "Application",
      "Security",
      "System",
      "Setup",
      "Microsoft-Windows-AAD/Operational",
      "Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider/Admin",
    ]);
  });

  it("does not depend on the order the names arrived in", () => {
    expect(orderChannelNames([...names].reverse())).toEqual(orderChannelNames(names));
  });

  it("lists a name once however often it is given", () => {
    expect(orderChannelNames(["System", "Application", "System"])).toEqual([
      "Application",
      "System",
    ]);
  });

  it("returns nothing for no names", () => {
    expect(orderChannelNames([])).toEqual([]);
  });

  it("visits a node's own channel before the channels beneath it", () => {
    expect(
      orderChannelNames(["Fabrikam/Operational", "Contoso/Operational", "Contoso"]),
    ).toEqual(["Contoso", "Contoso/Operational", "Fabrikam/Operational"]);
  });

  it("orders a service channel among its siblings by name", () => {
    expect(
      orderChannelNames([
        "Microsoft-Windows-Shell-Core/Operational",
        "Microsoft-Windows-AAD/Operational",
        "Microsoft-Windows-AAD/Analytic",
      ]),
    ).toEqual([
      "Microsoft-Windows-AAD/Analytic",
      "Microsoft-Windows-AAD/Operational",
      "Microsoft-Windows-Shell-Core/Operational",
    ]);
  });

  it("matches the order the tree renders, which is where the pane takes its rows from", () => {
    const tree = buildChannelTree(names.map((name) => ({ name })));
    const rendered: string[] = tree.windowsLogs.map((channel) => channel.name);
    const walk = (node: typeof tree.serviceTree) => {
      for (const child of [...node.children.values()].sort((a, b) => a.name.localeCompare(b.name))) {
        if (child.channel) rendered.push(child.channel.name);
        walk(child);
      }
    };
    walk(tree.serviceTree);
    expect(orderChannelNames(names)).toEqual(rendered);
  });
});

describe("text-log channels", () => {
  const event = (channel: string) => ({ channel, originKind: "event" as const });
  const log = (channel: string) => ({ channel, originKind: "log" as const });
  const legacy = (channel: string) => ({ channel });

  it("finds the channels whose records are all text-log records", () => {
    const records = [
      event("System"),
      log("bundle.zip::logs/app.log"),
      log("bundle.zip::logs/app.log"),
      log("bundle.zip::logs/other.log"),
    ];
    expect([...textLogChannelNames(records)].sort()).toEqual([
      "bundle.zip::logs/app.log",
      "bundle.zip::logs/other.log",
    ]);
    expect(isTextLogChannel("bundle.zip::logs/app.log", records)).toBe(true);
    expect(isTextLogChannel("System", records)).toBe(false);
  });

  it("does not call a channel a text log when any of its records is an event", () => {
    const records = [log("Mixed"), event("Mixed")];
    expect(textLogChannelNames(records).has("Mixed")).toBe(false);
    expect(isTextLogChannel("Mixed", records)).toBe(false);
  });

  it("treats a record with no origin as an event, and a channel with no records as no text log", () => {
    expect(textLogChannelNames([legacy("System")]).size).toBe(0);
    expect(isTextLogChannel("System", [legacy("System")])).toBe(false);
    expect(isTextLogChannel("Unknown", [event("System")])).toBe(false);
  });
});
