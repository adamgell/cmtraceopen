import { describe, expect, it } from "vitest";

import { COLLECTION_SCAFFOLD_MESSAGE } from "../src/collect";

describe("download collection command scaffold", () => {
  it("provides an honest inactive status instead of collecting early", () => {
    expect(COLLECTION_SCAFFOLD_MESSAGE).toBe(
      "Download collection is not active yet; collection logic will be added in a later task.",
    );
  });
});
