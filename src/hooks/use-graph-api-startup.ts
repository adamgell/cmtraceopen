import { useUiStore } from "../stores/ui-store";
import { useIntuneStore } from "../workspaces/intune/intune-store";
import { buildGraphRegistryEntries } from "../lib/graph-registry";
import {
  graphAuthenticate,
  graphFetchAllApps,
  type GraphAppInfo,
} from "../lib/commands";

type GraphConnectionStatus = "idle" | "connecting" | "connected" | "error";

export interface GraphStartupDependencies {
  authenticate: typeof graphAuthenticate;
  fetchAllApps: typeof graphFetchAllApps;
  mergeApps(apps: GraphAppInfo[]): void;
  setConnectionStatus(status: GraphConnectionStatus): void;
  isCurrent(): boolean;
}

const defaultDependencies: GraphStartupDependencies = {
  authenticate: graphAuthenticate,
  fetchAllApps: graphFetchAllApps,
  mergeApps: (apps) =>
    useIntuneStore
      .getState()
      .mergeGuidRegistry(buildGraphRegistryEntries(apps)),
  setConnectionStatus: (status) =>
    useUiStore.getState().setGraphApiStatus(status),
  isCurrent: () => useUiStore.getState().graphApiEnabled,
};

export async function connectAndPopulate(
  dependencies: GraphStartupDependencies = defaultDependencies,
) {
  if (!dependencies.isCurrent()) return;
  dependencies.setConnectionStatus("connecting");

  let status;
  try {
    status = await dependencies.authenticate();
  } catch {
    if (dependencies.isCurrent()) {
      dependencies.setConnectionStatus("error");
    }
    return;
  }
  if (!dependencies.isCurrent()) return;
  if (!status.isAuthenticated) {
    dependencies.setConnectionStatus("error");
    return;
  }

  dependencies.setConnectionStatus("connected");
  try {
    if (status.capabilities.apps) {
      const apps = await dependencies.fetchAllApps();
      if (apps.length > 0 && dependencies.isCurrent()) {
        dependencies.mergeApps(apps);
      }
    }
  } catch {
    // Authentication remains valid when optional app-cache hydration fails.
  }
}

function tryStart() {
  const { graphApiEnabled, currentPlatform } = useUiStore.getState();
  if (!graphApiEnabled || currentPlatform !== "windows") return;
  let current = true;
  const unsubscribe = useUiStore.subscribe((state, previous) => {
    if (
      state.graphApiEnabled !== previous.graphApiEnabled ||
      state.currentPlatform !== previous.currentPlatform
    ) {
      current = false;
    }
  });
  void connectAndPopulate({
    ...defaultDependencies,
    isCurrent: () =>
      current &&
      useUiStore.getState().graphApiEnabled &&
      useUiStore.getState().currentPlatform === "windows",
  }).finally(unsubscribe);
}

if (useUiStore.persist.hasHydrated()) {
  tryStart();
} else {
  useUiStore.persist.onFinishHydration(tryStart);
}
