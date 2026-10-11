import { describe, expect, it } from "vitest";
import {
  buildChannelTree,
  isEvtxMemberName,
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

describe("text-log channels with no records", () => {
  const MEMBER = "C:\\cases\\bundle.zip::logs/AgentExecutor.log";
  const event = (channel: string) => ({ channel, originKind: "event" as const });

  it("recognizes a member the open reported as text, whatever it is called", () => {
    // An empty, wholly unparseable or zero-line member kept no record to say what it is.
    const archiveMembers = [{ path: "plain-name", kind: "text" as const }];
    expect([...textLogChannelNames([], { channels: ["plain-name", "System"], archiveMembers })]).toEqual([
      "plain-name",
    ]);
    expect(isTextLogChannel("plain-name", [], { archiveMembers })).toBe(true);
    expect(isTextLogChannel("plain-name", [])).toBe(false);
  });

  it("does not take an EVTX or binary member the open reported for a text log", () => {
    const archiveMembers = [
      { path: "evtx-member", kind: "evtx" as const },
      { path: "binary-member", kind: "binary" as const },
    ];
    expect(
      textLogChannelNames([], { channels: ["evtx-member", "binary-member"], archiveMembers }).size,
    ).toBe(0);
  });

  it("recognizes {archive}::{member} when the member is not an EVTX name", () => {
    expect([...textLogChannelNames([], { channels: [MEMBER, "System"] })]).toEqual([MEMBER]);
    expect(isTextLogChannel(MEMBER, [])).toBe(true);
  });

  it("keeps an EVTX member, a rotation included, a channel", () => {
    for (const member of [
      "bundle.zip::logs/System.evtx",
      "bundle.zip::logs/System.EVTX",
      "bundle.zip::logs/System.evtx.1",
      "bundle.zip::System.evtx.20",
    ]) {
      expect(textLogChannelNames([], { channels: [member] }).size).toBe(0);
      expect(isTextLogChannel(member, [])).toBe(false);
    }
  });

  it("lets an event record win over every name rule", () => {
    expect(textLogChannelNames([event(MEMBER)], { channels: [MEMBER] }).size).toBe(0);
    expect(isTextLogChannel(MEMBER, [event(MEMBER)])).toBe(false);
  });

  it("does not take a plain channel name for a text log", () => {
    expect(textLogChannelNames([], { channels: ["System", "Microsoft-Windows-AAD/Operational"] }).size).toBe(0);
  });
});

describe("isEvtxMemberName", () => {
  it.each([
    ["System.evtx", true],
    ["logs/System.evtx", true],
    ["logs/System.EVTX", true],
    ["logs/System.evtx.1", true],
    ["logs/System.evtx.123", true],
    ["logs/System.evtx.", false],
    ["logs/System.evtx.old", false],
    ["logs/.evtx.1", false],
    ["logs/app.log", false],
    ["logs.evtx/app.log", false],
  ])("%s -> %s", (name, expected) => {
    expect(isEvtxMemberName(name)).toBe(expected);
  });
});
