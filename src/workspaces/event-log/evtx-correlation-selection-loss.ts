/**
 * What the Correlation view says when something it was showing is gone: the chain that was selected,
 * or the "Not placed" pane that has nothing left to list.
 *
 * A loss is an EVENT, recorded once at the reconcile that found it (`SelectionLoss`), never a flag the
 * renders go on reading. What is said about it is derived from the record and from what exists NOW:
 *
 * - it is said only while it is still true: a chain that has come back, a pane that is shown again, or
 *   unplaced items that are listed again make the sentence false, so it is no longer said;
 * - it names a chain only when a chain is shown ("showing another" with zero chains is a false claim);
 * - the polite region says it until it has published it once (`announced`), and not again after a later
 *   model or "updating" change re-composes the announcement. A publication counts only if it was made
 *   AFTER the record was created (the record captures the publication count), because the region can
 *   still hold an earlier loss's sentence, and one kind's zero-chain wording is a prefix of its
 *   chain-shown wording.
 *
 * Pure: it reads no store and draws nothing.
 */

export interface SelectionLoss {
  /** "chain": the selected chain is gone. "unplaced": the Not placed pane was open with nothing left to list. */
  kind: "chain" | "unplaced";
  /** The id of the chain that was selected and is gone; null for the pane. */
  lostId: string | null;
  /** True once the polite region has published the sentence, which it is then not given again. */
  announced: boolean;
  /** How many publications the polite region had made when the record was created. */
  since: number;
}

/** What the polite region holds: the text it last published, and how many publications it has made. */
export interface Region {
  text: string;
  publications: number;
}

/** What exists now. */
export interface LossFacts {
  /** The ids of the chains of the model on show. */
  chainIds: readonly string[];
  /** The Not placed pane is the thing shown. */
  showPane: boolean;
  /** The model lists unplaced items (the Not placed row exists). */
  unplacedPresent: boolean;
  /** A chain is shown. */
  chainShown: boolean;
}

/** A new, unspoken loss, made when the region had made `publications` publications. */
export function newSelectionLoss(
  kind: SelectionLoss["kind"],
  lostId: string | null,
  publications: number,
): SelectionLoss {
  return { kind, lostId, announced: false, since: publications };
}

/**
 * Whether the region has now said the sentence of this loss. Not by looking for the text in whatever
 * the region holds: that can be a publication made before the record existed, and a prefix of
 * another sentence. It has been said when
 * - the announcement composed with it is identical to what the region already holds (the region
 *   would not publish it again, so it would otherwise sit in every later announcement); or
 * - a publication made AFTER the record was created carries the sentence.
 */
export function lossWasSaid(
  loss: SelectionLoss,
  sentence: string | null,
  region: Region,
  composed: string,
): boolean {
  if (loss.announced || sentence === null) return false;
  if (composed === region.text) return true;
  return region.publications > loss.since && region.text.includes(sentence);
}

/** Whether what the record says is still the case. A pane that is shown is not "left". */
export function lossStillTrue(loss: SelectionLoss, facts: LossFacts): boolean {
  if (facts.showPane) return false;
  if (loss.kind === "unplaced") return !facts.unplacedPresent;
  return loss.lostId === null || !facts.chainIds.includes(loss.lostId);
}

/**
 * The sentence for the polite region, or null when there is nothing to say: it was said, or it is no
 * longer true.
 */
export function spokenLoss(loss: SelectionLoss | null, facts: LossFacts): string | null {
  if (loss === null || loss.announced || !lossStillTrue(loss, facts)) return null;
  if (loss.kind === "unplaced") {
    return facts.chainShown
      ? "Nothing is listed under Not placed any more, showing a chain"
      : "Nothing is listed under Not placed any more";
  }
  return facts.chainShown
    ? "The selected chain is no longer present, showing another"
    : "The selected chain is no longer present";
}

/**
 * The notice shown with the chain, which stays until the operator picks while it is still true. Only a
 * lost chain has one: the pane that was left is not a chain the operator was looking at.
 */
export function visibleLoss(loss: SelectionLoss | null, facts: LossFacts): string | null {
  if (loss === null || loss.kind !== "chain" || !lossStillTrue(loss, facts)) return null;
  return facts.chainShown
    ? "The chain that was selected is no longer present. Another chain is shown."
    : "The chain that was selected is no longer present.";
}
