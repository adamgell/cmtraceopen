/**
 * `useThrottledValue` publishes a changing value at most once per interval. The Correlation view
 * announces through it (at most once every 5 s, spec 10) and the Insights rail debounces its card
 * data with it.
 */
import { act, renderHook } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { useThrottledValue } from "./use-throttled-value";

beforeEach(() => {
  vi.useFakeTimers();
});
afterEach(() => {
  vi.useRealTimers();
});

describe("useThrottledValue", () => {
  it("publishes the first value at once", () => {
    const { result } = renderHook(() => useThrottledValue("first", 5_000));
    expect(result.current).toBe("first");
  });

  it("holds a change until the interval ends, then publishes the latest value", () => {
    const { result, rerender } = renderHook(({ value }) => useThrottledValue(value, 5_000), {
      initialProps: { value: "a" },
    });
    rerender({ value: "b" });
    rerender({ value: "c" });
    expect(result.current).toBe("a");
    act(() => {
      vi.advanceTimersByTime(4_999);
    });
    expect(result.current).toBe("a");
    act(() => {
      vi.advanceTimersByTime(1);
    });
    expect(result.current).toBe("c");
  });

  it("does not restart the interval on every change, so a value that never goes quiet is still published", () => {
    const { result, rerender } = renderHook(({ value }) => useThrottledValue(value, 5_000), {
      initialProps: { value: 0 },
    });
    for (let i = 1; i <= 4; i += 1) {
      rerender({ value: i });
      act(() => {
        vi.advanceTimersByTime(1_000);
      });
    }
    expect(result.current).toBe(0);
    act(() => {
      vi.advanceTimersByTime(1_000);
    });
    expect(result.current).toBe(4);
  });

  it("publishes nothing after it unmounts", () => {
    const { result, rerender, unmount } = renderHook(({ value }) => useThrottledValue(value, 5_000), {
      initialProps: { value: "a" },
    });
    rerender({ value: "b" });
    unmount();
    act(() => {
      vi.advanceTimersByTime(10_000);
    });
    expect(result.current).toBe("a");
  });
});
