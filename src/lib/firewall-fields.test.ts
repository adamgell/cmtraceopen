import { describe, expect, it } from "vitest";
import { firewallEntry } from "../test-utils/firewall";
import { getColumnsForParser, getColumnDef } from "./column-config";
import { compareEntryTimes, firewallField, firewallSearchText } from "./firewall-fields";
import { formatLogEntryTimestamp } from "./date-time-format";
import { filterByTimeRange } from "./diff-entries";
import { useLogStore } from "../stores/log-store";

describe("firewall field and time contracts", () => {
  it("exposes default fields without overloading HTTP or DNS", () => {
    expect(getColumnsForParser("windowsFirewall")).toEqual(["severity", "dateTime", "message", "firewallAction", "firewallProtocol", "firewallSourceIp", "firewallSourcePort", "firewallDestinationIp", "firewallDestinationPort", "firewallPath"]);
    expect(getColumnDef("firewallAction")?.accessor(firewallEntry())).toBe("ALLOW");
    expect(firewallField(firewallEntry(), "PID")).toBe("8801");
    expect(firewallField(firewallEntry(), "absent")).toBeNull();
  });
  it.each(["2042-03-09 02:30:00", "2042-11-02 01:30:00", "2042-03-30 01:30:00", "2042-10-26 01:30:00", "2042-99-44 invalid"])("preserves literal Local and unknown %s in every viewer zone", timestampDisplay => {
    for (const timeBasis of ["local", "unknown"] as const) {
      const entry = firewallEntry({ timestampDisplay }); entry.firewall!.timeBasis = timeBasis;
      expect(formatLogEntryTimestamp(entry)).toBe(timestampDisplay);
      expect(entry.timestamp).toBeNull();
    }
  });
  it("retains an explicit UTC label including genuine epoch zero", () => {
    const entry = firewallEntry({ timestamp: 0, timestampDisplay: "1970-01-01 00:00:00 UTC" });
    entry.firewall!.timeBasis = "utc";
    expect(formatLogEntryTimestamp(entry)).toBe("1970-01-01 00:00:00 UTC");
    expect(filterByTimeRange([firewallEntry(), entry], -1, 1)).toEqual([entry]);
  });
  it("sorts validated wall-clock tuples only within a source and preserves physical invalid ties", () => {
    const early = firewallEntry({ lineNumber: 6, timestampDisplay: "2042-04-05 01:00:00" });
    const late = firewallEntry({ lineNumber: 4, timestampDisplay: "2042-04-05 23:00:00" });
    expect(compareEntryTimes(early, late)).toBeLessThan(0);
    const invalid = firewallEntry({ lineNumber: 7, timestampDisplay: "2042-02-30 23:00:00" });
    const invalid2 = firewallEntry({ lineNumber: 9, timestampDisplay: "not a time" });
    expect(compareEntryTimes(invalid, invalid2)).toBeLessThan(0);
    expect(compareEntryTimes({ ...late, filePath: "/synthetic/a.log" }, { ...early, filePath: "/synthetic/b.log" })).toBeLessThan(0);
    expect(compareEntryTimes(firewallEntry({ timestamp: 0 }), early)).toBeLessThan(0);
  });
  it("finds values omitted from the message, including unknown columns and flags", () => {
    const entry = firewallEntry();
    entry.firewall!.declaredFields.push("tcpflags", "invented-extra");
    entry.firewall!.fields.push({ name: "tcpflags", value: "SYN-TEST" }, { name: "invented-extra", value: "invented-marker" });
    expect(firewallSearchText(entry)).toContain("invented-marker");
    const store = useLogStore.getState(); store.clear(); store.setEntries([entry]); store.setActiveColumns(["message"]);
    for (const query of ["8801", "SYN-TEST", "invented-marker"]) { store.setFindQuery(query); store.recomputeFindMatches(); expect(useLogStore.getState().findMatchIds).toEqual([entry.id]); }
  });
  it("keeps mixed ordinary and firewall timestamp sorting transitive across permutations", () => {
    const ordinary = { ...firewallEntry({ id: 10, timestamp: null }), firewall: undefined };
    const dated = { ...ordinary, id: 11, timestamp: 1 };
    const utc = firewallEntry({ id: 12, timestamp: 2 });
    const local = firewallEntry({ id: 13, timestamp: null });
    const zero = firewallEntry({ id: 14, timestamp: 0 });
    const negative = firewallEntry({ id: 15, timestamp: -1 });
    const rows = [ordinary, dated, utc, local, zero, negative];
    function permutations<T>(items: T[]): T[][] {
      return items.length === 0 ? [[]] : items.flatMap((item, index) =>
        permutations(items.filter((_, i) => i !== index)).map(rest => [item, ...rest]));
    }
    for (const permutation of permutations(rows)) {
      const sorted = [...permutation].sort(compareEntryTimes);
      expect(sorted.map(row => row.timestamp ?? (row.firewall ? null : 0))).toEqual([-1, 0, 0, 1, 2, null]);
      // Epoch-zero ties retain input order; no arbitrary tie-breaker is needed.
      expect(sorted.slice(1, 3).map(row => row.id)).toEqual(permutation.filter(row => row.id === 10 || row.id === 14).map(row => row.id));
    }
    for (const a of rows) for (const b of rows) for (const c of rows) {
      if (compareEntryTimes(a, b) <= 0 && compareEntryTimes(b, c) <= 0) {
        expect(compareEntryTimes(a, c)).toBeLessThanOrEqual(0);
      }
    }
    expect(compareEntryTimes(ordinary, { ...dated, timestamp: -1 })).toBeGreaterThan(0);
    expect(compareEntryTimes(ordinary, { ...dated, timestamp: 0 })).toBe(0);
  });
});
