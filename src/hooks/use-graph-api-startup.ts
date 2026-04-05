import { useUiStore } from "../stores/ui-store";
import { useIntuneStore } from "../workspaces/intune/intune-store";
import { buildGraphRegistryEntries } from "../lib/graph-registry";
import {
  graphAuthenticate,
  graphFetchAllApps,
} from "../lib/commands";

async function connectAndPopulate() {
  try {
    useUiStore.getState().setGraphApiStatus("connecting");

    const status = await graphAuthenticate();
    if (!status.isAuthenticated) {
      useUiStore.getState().setGraphApiStatus("error");
      return;
    }

    const apps = await graphFetchAllApps();
    if (apps.length > 0) {
      useIntuneStore.getState().mergeGuidRegistry(buildGraphRegistryEntries(apps));
    }

    useUiStore.getState().setGraphApiStatus("connected");
  } catch {
    useUiStore.getState().setGraphApiStatus("error");
  }
}

function tryStart() {
  const { graphApiEnabled, currentPlatform } = useUiStore.getState();
  if (!graphApiEnabled || currentPlatform !== "windows") return;
  connectAndPopulate();
}

if (useUiStore.persist.hasHydrated()) {
  tryStart();
} else {
  useUiStore.persist.onFinishHydration(tryStart);
}
