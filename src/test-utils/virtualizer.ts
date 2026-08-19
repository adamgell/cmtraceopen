import { vi } from "vitest";

export interface TestVirtualizerOptions {
  count: number;
  estimateSize?: (index: number) => number;
  getItemKey?: (index: number) => string | number;
}

export function createTestVirtualizer({
  count,
  estimateSize = () => 28,
  getItemKey,
}: TestVirtualizerOptions) {
  const sizes = Array.from({ length: count }, (_, index) => estimateSize(index));
  const starts: number[] = [];
  let totalSize = 0;
  for (const size of sizes) {
    starts.push(totalSize);
    totalSize += size;
  }

  return {
    getVirtualItems: () =>
      sizes.map((size, index) => ({
        index,
        key: getItemKey?.(index) ?? index,
        start: starts[index],
        size,
      })),
    getTotalSize: () => totalSize,
    measureElement: vi.fn(),
    scrollToIndex: vi.fn(),
  };
}
