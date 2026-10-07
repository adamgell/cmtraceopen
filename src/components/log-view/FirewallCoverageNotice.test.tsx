import { cleanup, render, screen } from "@testing-library/react";
import { afterEach, expect, it } from "vitest";
import { firewallCoverage, firewallSnapshot } from "../../test-utils/firewall";
import { useLogStore } from "../../stores/log-store";
import { FirewallCoverageNotice } from "./FirewallCoverageNotice";
afterEach(cleanup);
it("shows one cumulative source notice for coverage and decoding", () => {
  const snapshot = firewallSnapshot(); snapshot.firewallCoverage = firewallCoverage({ padding: { count: "2048", lines: [1] }, malformed: { count: "2", lines: [4] }, oversized: { count: "1", lines: [5] }, lossEvents: { count: "2", lines: [6, 7] }, lostEvents: { count: "12", lines: [6] }, unknownLossCount: { count: "1", lines: [7] }, unplacedTimestamps: { count: "3", lines: [4, 5, 6] } });
  snapshot.firewallDecoding = { kind: "pending", pendingBytes: 2, reason: null };
  useLogStore.getState().clear(); useLogStore.getState().registerFirewallSource(snapshot); useLogStore.setState({ openFilePath: snapshot.filePath, sourceOpenMode: "single-file" });
  const { rerender } = render(<FirewallCoverageNotice />);
  expect(screen.getAllByRole("status")).toHaveLength(1);
  for (const text of ["2048 NUL padding characters skipped", "2 malformed", "1 oversized", "12 known lost", "1 loss event with unknown count", "3 without absolute time", "2 undecoded bytes"]) expect(screen.getByRole("status")).toHaveTextContent(text);
  useLogStore.getState().registerFirewallSource({ ...snapshot, firewallSessionId: "gap-session", firewallDecoding: { kind: "gap", pendingBytes: 0, reason: "invalidEncoding" } });
  rerender(<FirewallCoverageNotice />);
  expect(screen.getByRole("status")).toHaveTextContent("Decoding gap: invalid encoding");
});
