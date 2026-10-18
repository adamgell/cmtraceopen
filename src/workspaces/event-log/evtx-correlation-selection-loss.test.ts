/**
 * What the view says about a loss is derived from the event record and from what exists now. These
 * tests pin each sentence to the state in which it is true, and to no other.
 */
import { describe, expect, it } from "vitest";
import {
  lossStillTrue,
  newSelectionLoss,
  spokenLoss,
  visibleLoss,
  type LossFacts,
  type SelectionLoss,
} from "./evtx-correlation-selection-loss";

const facts = (extra: Partial<LossFacts> = {}): LossFacts => ({
  chainIds: ["a", "b"],
  showPane: false,
  unplacedPresent: false,
  chainShown: true,
  ...extra,
});
const chainLoss = (): SelectionLoss => newSelectionLoss("chain", "gone");
const paneLoss = (): SelectionLoss => newSelectionLoss("unplaced", null);

describe("a lost chain", () => {
  it("says another chain is shown only when a chain is shown", () => {
    expect(spokenLoss(chainLoss(), facts())).toBe("The selected chain is no longer present, showing another");
    expect(visibleLoss(chainLoss(), facts())).toBe(
      "The chain that was selected is no longer present. Another chain is shown.",
    );
  });

  it("names no other chain when there are none", () => {
    const none = facts({ chainIds: [], chainShown: false });
    expect(spokenLoss(chainLoss(), none)).toBe("The selected chain is no longer present");
    expect(visibleLoss(chainLoss(), none)).toBe("The chain that was selected is no longer present.");
    expect(`${spokenLoss(chainLoss(), none)} ${visibleLoss(chainLoss(), none)}`).not.toMatch(/another|showing/i);
  });

  it("is not said once the chain is back in the model, which makes 'no longer present' false", () => {
    const back = facts({ chainIds: ["a", "gone"] });
    expect(lossStillTrue(chainLoss(), back)).toBe(false);
    expect(spokenLoss(chainLoss(), back)).toBeNull();
    expect(visibleLoss(chainLoss(), back)).toBeNull();
  });

  it("is not said while the Not placed pane is the thing shown", () => {
    const pane = facts({ showPane: true, chainShown: false });
    expect(spokenLoss(chainLoss(), pane)).toBeNull();
    expect(visibleLoss(chainLoss(), pane)).toBeNull();
  });

  it("is spoken once: after the region published it, only the notice that stays remains", () => {
    const said = { ...chainLoss(), announced: true };
    expect(spokenLoss(said, facts())).toBeNull();
    expect(visibleLoss(said, facts())).toBe(
      "The chain that was selected is no longer present. Another chain is shown.",
    );
  });
});

describe("a Not placed pane that was left", () => {
  it("says a chain is shown only when one is", () => {
    expect(spokenLoss(paneLoss(), facts())).toBe("Nothing is listed under Not placed any more, showing a chain");
    expect(spokenLoss(paneLoss(), facts({ chainIds: [], chainShown: false }))).toBe(
      "Nothing is listed under Not placed any more",
    );
  });

  it("is not said when the items are listed again, whether or not the pane is open", () => {
    expect(lossStillTrue(paneLoss(), facts({ unplacedPresent: true }))).toBe(false);
    expect(spokenLoss(paneLoss(), facts({ unplacedPresent: true }))).toBeNull();
    expect(spokenLoss(paneLoss(), facts({ unplacedPresent: true, showPane: true }))).toBeNull();
    expect(spokenLoss(paneLoss(), facts({ showPane: true }))).toBeNull();
  });

  it("is not said again after it was said, and has no notice that stays", () => {
    expect(spokenLoss({ ...paneLoss(), announced: true }, facts())).toBeNull();
    expect(visibleLoss(paneLoss(), facts())).toBeNull();
  });
});

describe("no loss", () => {
  it("says nothing", () => {
    expect(spokenLoss(null, facts())).toBeNull();
    expect(visibleLoss(null, facts())).toBeNull();
  });

  it("starts unspoken", () => {
    expect(newSelectionLoss("chain", "x")).toEqual({ kind: "chain", lostId: "x", announced: false });
  });
});
