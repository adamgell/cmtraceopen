import { useEffect, useRef, useState } from "react";

/**
 * `value`, published at most once per `delayMs`: the first change starts a timer that publishes the
 * latest value when it fires, and further changes do not restart it (the analysis pump's precedent).
 * A pure trailing debounce would starve the cards while a tail never goes quiet for the delay. The
 * first value is immediate.
 */
export function useThrottledValue<T>(value: T, delayMs: number): T {
  const [published, setPublished] = useState(value);
  const latestRef = useRef(value);
  const timerRef = useRef<number | null>(null);
  latestRef.current = value;
  useEffect(() => {
    if (Object.is(published, value) || timerRef.current !== null) return;
    timerRef.current = window.setTimeout(() => {
      timerRef.current = null;
      setPublished(latestRef.current);
    }, delayMs);
  }, [value, published, delayMs]);
  useEffect(
    () => () => {
      if (timerRef.current !== null) window.clearTimeout(timerRef.current);
      timerRef.current = null;
    },
    [],
  );
  return published;
}
