/**
 * The channel-clear workflow on its own, driven with a fake `clearChannel` and a fake set of
 * loaded channels instead of the event-log store.
 *
 * The picker's own suite (`evtx-live-ops.test.tsx`) covers the workflow through the rendered
 * controls: Cancel and Escape returning focus to the select, the modal queue, the status taking
 * focus while a clear runs, the alert taking it after a clear fails, the select taking it after a
 * clear succeeds while other channels stay loaded, a settled clear leaving alone focus the operator
 * moved elsewhere, and the filter taking focus when a control the operator moved it to is removed.
 *
 * This file covers the rest: the single-flight guard, every result the store can return, a chosen
 * channel that stops being loaded, the dialog's fallback to the filter when the select is not
 * mounted, and where focus goes when a clear succeeds while its status holds focus: back to the
 * select, or to the filter when the clear removed the last loaded channel and the controls with it.
 */
import { act, renderHook } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { EvtxClearStatusResult } from "../../lib/commands";
import { useUiStore } from "../../stores/ui-store";
import { deferred } from "../../test-utils/deferred";
import { useChannelClear, type ChannelClearOptions } from "./use-channel-clear";

function setup(loaded: readonly string[] = ["Application", "System"]) {
  const pending: Array<ReturnType<typeof deferred<EvtxClearStatusResult>>> = [];
  const clearChannel = vi.fn((_channel: string, _confirmed: boolean) => {
    const result = deferred<EvtxClearStatusResult>();
    pending.push(result);
    return result.promise;
  });
  const filter = document.createElement("input");
  const select = document.createElement("select");
  document.body.append(filter, select);
  const options: ChannelClearOptions = {
    clearChannel,
    loadedChannels: new Set(loaded),
    channelFilterRef: { current: filter },
  };
  const hook = renderHook((props: ChannelClearOptions) => useChannelClear(props), {
    initialProps: options,
  });
  hook.result.current.selectRef.current = select;

  /** Mounts the "Clearing" status, wired to the workflow's focus handlers as the controls wire it. */
  const mountStatus = () => {
    const status = document.createElement("div");
    status.tabIndex = -1;
    status.addEventListener("focus", () => hook.result.current.onStatusFocus());
    status.addEventListener("blur", () => hook.result.current.onStatusBlur());
    document.body.append(status);
    hook.result.current.statusRef.current = status;
    return status;
  };

  /** Chooses `channel`, asks for confirmation and confirms, as the controls do. */
  const confirmClear = (channel = "Application") => {
    act(() => hook.result.current.chooseTarget(channel));
    act(() => hook.result.current.requestConfirmation());
    act(() => hook.result.current.confirm());
  };
  const settle = async (outcome: EvtxClearStatusResult | { reject: unknown }, index = 0) => {
    await act(async () => {
      if ("reject" in outcome) pending[index].reject(outcome.reject);
      else pending[index].resolve(outcome);
      await pending[index].promise.catch(() => undefined);
    });
  };
  const setLoaded = (next: readonly string[]) =>
    hook.rerender({ ...options, loadedChannels: new Set(next) });

  return { hook, clearChannel, filter, select, mountStatus, confirmClear, settle, setLoaded };
}

describe("useChannelClear", () => {
  beforeEach(() => {
    useUiStore.setState(useUiStore.getInitialState(), true);
  });

  afterEach(() => {
    document.body.replaceChildren();
  });

  it("starts one clear of the chosen channel and no second one until it settles", async () => {
    const { hook, clearChannel, confirmClear, settle } = setup();

    confirmClear();

    expect(clearChannel).toHaveBeenCalledTimes(1);
    expect(clearChannel).toHaveBeenCalledWith("Application", true);
    expect(hook.result.current.clearingChannel).toBe("Application");
    expect(hook.result.current.confirmationOpen).toBe(false);

    act(() => hook.result.current.confirm());
    expect(clearChannel).toHaveBeenCalledTimes(1);

    await settle({ status: "cleared" });

    expect(hook.result.current.clearingChannel).toBeNull();
    expect(hook.result.current.target).toBeNull();
    expect(hook.result.current.error).toBeNull();
  });

  it("neither asks for confirmation nor clears while no channel is chosen", () => {
    const { hook, clearChannel } = setup();

    act(() => hook.result.current.requestConfirmation());
    expect(hook.result.current.confirmationOpen).toBe(false);
    expect(useUiStore.getState().modalOwner).toBeNull();

    act(() => hook.result.current.confirm());
    expect(clearChannel).not.toHaveBeenCalled();
    expect(hook.result.current.clearingChannel).toBeNull();
  });

  it("shows the confirmation through the app's modal queue", () => {
    const { hook } = setup();

    act(() => hook.result.current.chooseTarget("System"));
    act(() => hook.result.current.requestConfirmation());

    expect(hook.result.current.confirmationOpen).toBe(true);
    expect(useUiStore.getState().modalOwner).toBe("eventLogChannelClear");

    act(() => hook.result.current.cancelConfirmation());

    expect(hook.result.current.confirmationOpen).toBe(false);
    expect(useUiStore.getState().modalOwner).toBeNull();
  });

  it.each([
    [{ status: "denied", detail: "Access is denied" }, "Access is denied"],
    [{ status: "unavailable", detail: "Remote RPC unavailable" }, "Remote RPC unavailable"],
    [{ status: "unsupported", detail: "Not on this platform" }, "Not on this platform"],
    [{ status: "cancelled" }, "Clear was cancelled."],
    [{ status: "empty" }, "Application is already empty."],
  ] as const)("announces a %o result and keeps the channel chosen", async (result, message) => {
    const { hook, confirmClear, settle } = setup();

    confirmClear();
    await settle(result);

    expect(hook.result.current.error).toBe(message);
    expect(hook.result.current.target).toBe("Application");
    expect(hook.result.current.clearingChannel).toBeNull();
    expect(hook.result.current.confirmationOpen).toBe(false);
  });

  it.each([
    [new Error("Command 'evtx_clear_channel' failed."), "Command 'evtx_clear_channel' failed."],
    ["bridge closed", "bridge closed"],
  ])("announces a clear that rejects with %o", async (reason, message) => {
    const { hook, confirmClear, settle } = setup();

    confirmClear();
    await settle({ reject: reason });

    expect(hook.result.current.error).toBe(message);
    expect(hook.result.current.target).toBe("Application");
    expect(hook.result.current.clearingChannel).toBeNull();
  });

  it("drops the chosen channel and its error when the channel stops being loaded", async () => {
    const { hook, confirmClear, settle, setLoaded } = setup();
    confirmClear();
    await settle({ status: "denied", detail: "Access is denied" });
    expect(hook.result.current.error).toBe("Access is denied");

    act(() => setLoaded(["Application", "System"]));
    expect(hook.result.current.target).toBe("Application");

    act(() => setLoaded(["System"]));

    expect(hook.result.current.target).toBeNull();
    expect(hook.result.current.error).toBeNull();
  });

  it("keeps the chosen channel while its clear runs, and drops it once the clear settles", async () => {
    const { hook, confirmClear, settle, setLoaded } = setup();
    confirmClear();

    act(() => setLoaded(["System"]));
    expect(hook.result.current.target).toBe("Application");
    expect(hook.result.current.clearingChannel).toBe("Application");

    await settle({ status: "denied", detail: "Access is denied" });

    expect(hook.result.current.target).toBeNull();
    expect(hook.result.current.error).toBeNull();
  });

  it("returns focus to the select when the confirmation closes, or to the filter without one", () => {
    const { hook, filter, select } = setup();
    act(() => hook.result.current.chooseTarget("Application"));

    act(() => hook.result.current.requestConfirmation());
    act(() => hook.result.current.onConfirmationOpenChange(false));
    expect(select).toHaveFocus();

    hook.result.current.selectRef.current = null;
    act(() => hook.result.current.requestConfirmation());
    act(() => hook.result.current.cancelConfirmation());
    expect(filter).toHaveFocus();
  });

  it("returns focus to the select after a clear succeeds while its status holds focus", async () => {
    const { hook, select, mountStatus, confirmClear, settle, setLoaded } = setup();
    const status = mountStatus();

    confirmClear();
    expect(status).toHaveFocus();

    // The store drops the cleared channel; System stays loaded, so the controls stay mounted.
    act(() => setLoaded(["System"]));
    await settle({ status: "cleared" });

    expect(hook.result.current.clearingChannel).toBeNull();
    expect(select).toHaveFocus();
  });

  it("moves focus to the filter when a clear removes the last loaded channel and the controls", async () => {
    const { hook, filter, select, mountStatus, confirmClear, settle, setLoaded } =
      setup(["Application"]);
    const status = mountStatus();

    confirmClear();
    expect(status).toHaveFocus();

    // The store drops the last loaded channel, so the picker unmounts the clear controls.
    act(() => setLoaded([]));
    hook.result.current.selectRef.current = null;
    select.remove();
    await settle({ status: "cleared" });

    expect(hook.result.current.clearingChannel).toBeNull();
    expect(filter).toHaveFocus();
  });
});
