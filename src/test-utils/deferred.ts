export function deferred<T>() {
  let resolvePromise: ((value: T) => void) | undefined;
  let rejectPromise: ((reason?: unknown) => void) | undefined;
  const promise = new Promise<T>((resolve, reject) => {
    resolvePromise = resolve;
    rejectPromise = reject;
  });

  return {
    promise,
    resolve(value: T) {
      if (!resolvePromise) {
        throw new Error("Deferred promise resolver was not initialized");
      }
      resolvePromise(value);
    },
    reject(reason: unknown) {
      if (!rejectPromise) {
        throw new Error("Deferred promise rejecter was not initialized");
      }
      rejectPromise(reason);
    },
  };
}
