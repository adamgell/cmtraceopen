/**
 * What the view says about a loss is derived from the event record and from what exists now. These
 * tests pin each sentence to the state in which it is true, and to no other.
 */
import { describe, expect, it } from "vitest";
import {
  lossStillTrue,
  lossWasSaid,
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
const chainLoss = (): SelectionLoss => newSelectionLoss("chain", "gone", 0);
const paneLoss = (): SelectionLoss => newSelectionLoss("unplaced", null, 0);

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

  it("starts unspoken, remembering how many publications the region had made", () => {
    expect(newSelectionLoss("chain", "x", 3)).toEqual({ kind: "chain", lostId: "x", announced: false, since: 3 });
  });
});

describe("when the region has said a loss", () => {
  const ZERO = "The selected chain is no longer present";
  const SHOWN = `${ZERO}, showing another`;
  const region = (text: string, publications: number) => ({ text, publications });
  /** A loss recorded when the region had made `since` publications. */
  const recorded = (since: number) => newSelectionLoss("chain", "gone", since);

  it("has not, until a publication made after the record carries its sentence", () => {
    const loss = recorded(2);
    expect(lossWasSaid(loss, SHOWN, region("7 chains", 3), "7 chains. " + SHOWN)).toBe(false);
    expect(lossWasSaid(loss, SHOWN, region("7 chains. " + SHOWN, 3), "7 chains. " + SHOWN)).toBe(true);
  });

  it("is not said by a publication made before the record, even one that holds the sentence", () => {
    // The region published this very sentence for an earlier loss (publication 2); a second loss is
    // recorded after it, and the new announcement differs (the count), so it still has to be published.
    const loss = recorded(2);
    expect(lossWasSaid(loss, SHOWN, region("7 chains. " + SHOWN, 2), "6 chains. " + SHOWN)).toBe(false);
    expect(lossWasSaid(loss, SHOWN, region("7 chains. " + SHOWN, 3), "6 chains. " + SHOWN)).toBe(true);
  });

  it("is not said by an earlier sentence that contains this one (the zero-chain wording is a prefix)", () => {
    const loss = recorded(2);
    expect(lossWasSaid(loss, ZERO, region("7 chains. " + SHOWN, 2), "0 chains. " + ZERO)).toBe(false);
    expect(lossWasSaid(loss, ZERO, region("0 chains. " + ZERO, 3), "0 chains. " + ZERO)).toBe(true);
  });

  it("has, with no publication, when the announcement is identical to what the region already holds", () => {
    const same = "7 chains. " + SHOWN;
    expect(lossWasSaid(recorded(5), SHOWN, region(same, 5), same)).toBe(true);
  });

  it("is not said by an identical announcement that does not carry the sentence (no model)", () => {
    // With no model the announcement is the "no analysis" or "reading" text, or empty: it never
    // carries the sentence, so a region that holds it has not said the loss.
    for (const text of ["No event analysis is available. Load events to see correlation.", "Reading correlation edges...", ""]) {
      expect(lossWasSaid(recorded(1), SHOWN, region(text, 2), text), JSON.stringify(text)).toBe(false);
    }
  });

  it("is never said twice, and has nothing to say with no sentence", () => {
    expect(lossWasSaid({ ...recorded(0), announced: true }, SHOWN, region(SHOWN, 9), SHOWN)).toBe(false);
    expect(lossWasSaid(recorded(0), null, region("7 chains", 9), "7 chains")).toBe(false);
  });
});
