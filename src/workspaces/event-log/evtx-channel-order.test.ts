import { describe, expect, it } from "vitest";
import { buildChannelTree, orderChannelNames } from "./evtx-channel-order";

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
