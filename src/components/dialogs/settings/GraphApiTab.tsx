import {
  useState,
  useEffect,
  useCallback,
  useRef,
  useSyncExternalStore,
} from "react";
import { tokens } from "@fluentui/react-components";
import { useUiStore } from "../../../stores/ui-store";
import {
  graphAuthenticate,
  graphGetAuthStatus,
  graphRequestMissingPermissions,
  graphSignOut,
  graphFetchAllApps,
  type GraphAuthStatus,
  type GraphPermissionUpgradeOutcome,
  type GraphPermissionUpgradeResult,
} from "../../../lib/commands";
import { useIntuneStore } from "../../../workspaces/intune/intune-store";
import { buildGraphRegistryEntries } from "../../../lib/graph-registry";

const GRAPH_CAPABILITY_ROWS = [
  [
    "Managed devices",
    "managedDevices",
    "DeviceManagementManagedDevices.Read.All",
  ],
  [
    "Service configuration",
    "serviceConfig",
    "DeviceManagementServiceConfig.Read.All",
  ],
  ["Apps", "apps", "DeviceManagementApps.Read.All"],
  ["Configuration", "configuration", "DeviceManagementConfiguration.Read.All"],
  ["Scripts", "scripts", "DeviceManagementScripts.Read.All"],
] as const;

const PERMISSION_NOTICE_COPY: Record<GraphPermissionUpgradeOutcome, string> = {
  upgraded:
    "Permissions updated. Additional Graph capabilities are now available.",
  unchanged:
    "No additional permissions were granted. A tenant administrator may need to approve the missing permissions.",
  cancelled:
    "Permission request cancelled. Your existing Graph permissions are unchanged.",
  denied:
    "Consent was not granted. Your existing Graph permissions remain available. A tenant administrator may need to approve the missing permissions.",
  failed:
    "Windows could not complete the permission request. Your existing Graph permissions remain available.",
  stale:
    "The permission request was superseded by a newer Graph connection change.",
};

type GraphAction = "signIn" | "signOut" | "cache" | "permissions";
type PermissionNoticeTone = "success" | "warning" | "error";

interface SharedGraphAction {
  action: GraphAction;
  generation: number;
  statusAtStart: GraphAuthStatus | null;
}

let graphActionGeneration = 0;
let sharedGraphAction: SharedGraphAction | null = null;
const graphActionSubscribers = new Set<() => void>();

function notifyGraphActionSubscribers() {
  for (const subscriber of graphActionSubscribers) {
    subscriber();
  }
}

function subscribeGraphAction(subscriber: () => void) {
  graphActionSubscribers.add(subscriber);
  return () => graphActionSubscribers.delete(subscriber);
}

function getSharedGraphAction() {
  return sharedGraphAction;
}

function beginSharedGraphAction(
  action: GraphAction,
  statusAtStart: GraphAuthStatus | null,
): number | null {
  if (sharedGraphAction !== null) return null;
  graphActionGeneration += 1;
  sharedGraphAction = {
    action,
    generation: graphActionGeneration,
    statusAtStart,
  };
  notifyGraphActionSubscribers();
  return graphActionGeneration;
}

function isCurrentSharedGraphAction(generation: number) {
  return (
    sharedGraphAction?.generation === generation &&
    graphActionGeneration === generation &&
    useUiStore.getState().graphApiEnabled
  );
}

function finishSharedGraphAction(action: GraphAction, generation: number) {
  if (
    sharedGraphAction?.action !== action ||
    sharedGraphAction.generation !== generation ||
    graphActionGeneration !== generation
  ) {
    return;
  }
  sharedGraphAction = null;
  notifyGraphActionSubscribers();
}

function invalidateSharedGraphActions() {
  graphActionGeneration += 1;
  sharedGraphAction = null;
  notifyGraphActionSubscribers();
}

interface PermissionNotice {
  tone: PermissionNoticeTone;
  message: string;
}

const GRAPH_DISCONNECTED_RECONCILIATION_NOTICE: PermissionNotice = {
  tone: "error",
  message:
    "Microsoft Graph is no longer connected. Sign in again to request permissions.",
};

const GRAPH_COMPLETE_RECONCILIATION_NOTICE: PermissionNotice = {
  tone: "success",
  message: "Microsoft Graph permissions are already up to date.",
};

const GRAPH_FAILED_PERMISSION_NOTICE: PermissionNotice = {
  tone: "error",
  message: PERMISSION_NOTICE_COPY.failed,
};

function buildPermissionReconciliationNotice(
  status: GraphAuthStatus,
): PermissionNotice {
  if (!status.isAuthenticated) {
    return GRAPH_DISCONNECTED_RECONCILIATION_NOTICE;
  }
  if (status.missingScopes.length === 0) {
    return GRAPH_COMPLETE_RECONCILIATION_NOTICE;
  }
  return GRAPH_FAILED_PERMISSION_NOTICE;
}

function buildPermissionNotice(
  result: GraphPermissionUpgradeResult,
): PermissionNotice {
  const tone: PermissionNoticeTone =
    result.outcome === "upgraded"
      ? "success"
      : result.outcome === "unchanged" || result.outcome === "cancelled"
        ? "warning"
        : "error";
  const nativeMessage = result.message?.trim();
  const useNativeMessage =
    result.outcome === "denied" ||
    result.outcome === "failed" ||
    result.outcome === "stale";

  return {
    tone,
    message:
      useNativeMessage && nativeMessage
        ? nativeMessage
        : PERMISSION_NOTICE_COPY[result.outcome],
  };
}

function graphApiPhaseFromStatus(
  status: GraphAuthStatus,
): "connected" | "error" | "idle" {
  return status.isAuthenticated ? "connected" : status.error ? "error" : "idle";
}

export function GraphApiTab() {
  const graphApiEnabled = useUiStore((state) => state.graphApiEnabled);
  const setGraphApiEnabled = useUiStore((state) => state.setGraphApiEnabled);
  const currentPlatform = useUiStore((state) => state.currentPlatform);

  const [authStatus, setAuthStatus] = useState<GraphAuthStatus | null>(null);
  const [cachedAppCount, setCachedAppCount] = useState<number | null>(null);
  const [cacheError, setCacheError] = useState<string | null>(null);
  const [permissionNotice, setPermissionNotice] =
    useState<PermissionNotice | null>(null);
  const [showConfirmEnable, setShowConfirmEnable] = useState(false);
  const activeSharedAction = useSyncExternalStore(
    subscribeGraphAction,
    getSharedGraphAction,
    getSharedGraphAction,
  );
  const mountedRef = useRef(true);
  const localRefreshGeneration = useRef(0);
  const skipNextSettledActionRefresh = useRef(false);
  const activeAction = activeSharedAction?.action ?? null;
  const displayedAuthStatus =
    authStatus ?? activeSharedAction?.statusAtStart ?? null;
  const loading = activeAction === "signIn";
  const cacheLoading = activeAction === "cache";
  const permissionsLoading = activeAction === "permissions";
  const graphActionBusy = activeAction !== null;

  const isCurrentMountedGraphAction = useCallback((generation: number) => {
    return mountedRef.current && isCurrentSharedGraphAction(generation);
  }, []);

  useEffect(() => {
    mountedRef.current = true;
    return () => {
      mountedRef.current = false;
      localRefreshGeneration.current += 1;
    };
  }, []);

  const refreshStatus = useCallback(async () => {
    if (!graphApiEnabled || activeAction !== null) return;
    if (skipNextSettledActionRefresh.current) {
      skipNextSettledActionRefresh.current = false;
      return;
    }
    const localGeneration = ++localRefreshGeneration.current;
    const actionGenerationAtStart = graphActionGeneration;
    const isCurrentRefresh = () =>
      mountedRef.current &&
      localGeneration === localRefreshGeneration.current &&
      actionGenerationAtStart === graphActionGeneration &&
      sharedGraphAction === null &&
      useUiStore.getState().graphApiEnabled;
    try {
      const status = await graphGetAuthStatus();
      if (!isCurrentRefresh()) return;
      setAuthStatus(status);
      useUiStore.getState().setGraphApiStatus(graphApiPhaseFromStatus(status));
    } catch {
      if (isCurrentRefresh()) {
        useUiStore.getState().setGraphApiStatus("error");
      }
    }
  }, [activeAction, graphApiEnabled]);

  useEffect(() => {
    refreshStatus();
  }, [refreshStatus]);

  const handleToggle = (checked: boolean) => {
    if (checked) {
      setShowConfirmEnable(true);
    } else {
      invalidateSharedGraphActions();
      localRefreshGeneration.current += 1;
      setGraphApiEnabled(false);
      setAuthStatus(null);
      setCachedAppCount(null);
      setCacheError(null);
      setPermissionNotice(null);
      useUiStore.getState().setGraphApiStatus("idle");
    }
  };

  const confirmEnable = () => {
    setGraphApiEnabled(true);
    setShowConfirmEnable(false);
  };

  const beginGraphAction = (action: GraphAction): number | null => {
    return beginSharedGraphAction(action, displayedAuthStatus);
  };

  const finishGraphAction = (action: GraphAction, generation: number) => {
    if (mountedRef.current && isCurrentSharedGraphAction(generation)) {
      skipNextSettledActionRefresh.current = true;
    }
    finishSharedGraphAction(action, generation);
  };

  const handleSignIn = async () => {
    const generation = beginGraphAction("signIn");
    if (generation === null) return;
    setPermissionNotice(null);
    useUiStore.getState().setGraphApiStatus("connecting");
    try {
      const status = await graphAuthenticate();
      if (!isCurrentSharedGraphAction(generation)) return;
      useUiStore
        .getState()
        .setGraphApiStatus(status.isAuthenticated ? "connected" : "error");
      if (isCurrentMountedGraphAction(generation)) {
        setAuthStatus(status);
      }
    } catch (e) {
      if (!isCurrentSharedGraphAction(generation)) return;
      const status: GraphAuthStatus = {
        isAuthenticated: false,
        userPrincipalName: null,
        tenantId: null,
        grantedScopes: [],
        missingScopes: GRAPH_CAPABILITY_ROWS.map(([, , scope]) => scope),
        expiresAt: null,
        capabilities: {
          managedDevices: false,
          serviceConfig: false,
          apps: false,
          configuration: false,
          scripts: false,
        },
        error: e instanceof Error ? e.message : String(e),
      };
      useUiStore.getState().setGraphApiStatus("error");
      if (isCurrentMountedGraphAction(generation)) {
        setAuthStatus(status);
      }
    } finally {
      finishGraphAction("signIn", generation);
    }
  };

  const handleSignOut = async () => {
    const generation = beginGraphAction("signOut");
    if (generation === null) return;
    try {
      await graphSignOut();
      if (!isCurrentSharedGraphAction(generation)) return;
      useUiStore.getState().setGraphApiStatus("idle");
      if (isCurrentMountedGraphAction(generation)) {
        setAuthStatus(null);
        setCachedAppCount(null);
        setPermissionNotice(null);
      }
    } catch {
      // ignore
    } finally {
      finishGraphAction("signOut", generation);
    }
  };

  const handleRequestMissingPermissions = async () => {
    const generation = beginGraphAction("permissions");
    if (generation === null) return;
    setPermissionNotice(null);
    try {
      const result = await graphRequestMissingPermissions();
      if (!isCurrentSharedGraphAction(generation)) return;
      useUiStore
        .getState()
        .setGraphApiStatus(graphApiPhaseFromStatus(result.status));
      if (isCurrentMountedGraphAction(generation)) {
        setAuthStatus(result.status);
        setPermissionNotice(buildPermissionNotice(result));
      }
    } catch {
      if (!isCurrentSharedGraphAction(generation)) return;
      try {
        const status = await graphGetAuthStatus();
        if (!isCurrentSharedGraphAction(generation)) return;
        useUiStore
          .getState()
          .setGraphApiStatus(graphApiPhaseFromStatus(status));
        if (isCurrentMountedGraphAction(generation)) {
          setAuthStatus(status);
          setPermissionNotice(buildPermissionReconciliationNotice(status));
        }
      } catch {
        if (isCurrentMountedGraphAction(generation)) {
          setPermissionNotice(GRAPH_FAILED_PERMISSION_NOTICE);
        }
      }
    } finally {
      finishGraphAction("permissions", generation);
    }
  };

  const handlePrePopulateCache = async () => {
    const generation = beginGraphAction("cache");
    if (generation === null) return;
    setCacheError(null);
    setCachedAppCount(null);
    try {
      const apps = await graphFetchAllApps();
      if (!isCurrentMountedGraphAction(generation)) return;
      setCachedAppCount(apps.length);

      if (apps.length > 0) {
        useIntuneStore
          .getState()
          .mergeGuidRegistry(buildGraphRegistryEntries(apps));
      }
    } catch (e) {
      if (!isCurrentMountedGraphAction(generation)) return;
      const msg = e instanceof Error ? e.message : String(e);
      setCacheError(msg);
    } finally {
      finishGraphAction("cache", generation);
    }
  };

  if (currentPlatform !== "windows") {
    return (
      <div style={{ fontSize: "12px", color: tokens.colorNeutralForeground3 }}>
        Graph API integration is only available on Windows (Entra-joined
        devices).
      </div>
    );
  }

  return (
    <div>
      <div
        style={{
          fontSize: "12px",
          color: tokens.colorNeutralForeground3,
          marginBottom: "16px",
          lineHeight: 1.5,
        }}
      >
        Optionally connect to Microsoft Graph to resolve Intune app GUIDs to
        display names. This feature is off by default.
      </div>

      {/* Warning banner - always visible */}
      <div
        style={{
          padding: "10px 12px",
          marginBottom: "16px",
          borderRadius: "4px",
          backgroundColor: tokens.colorPaletteYellowBackground1,
          border: `1px solid ${tokens.colorPaletteYellowBorder1}`,
          fontSize: "11px",
          lineHeight: 1.6,
          color: tokens.colorNeutralForeground1,
        }}
      >
        <div style={{ fontWeight: 700, marginBottom: "4px" }}>
          Before you enable this feature:
        </div>
        <ul style={{ margin: "0", paddingLeft: "16px" }}>
          <li>
            This connects CMTrace Open to Microsoft Graph API using your Windows
            sign-in session (WAM).
          </li>
          <li>
            It sends read-only requests to your Intune tenant to resolve app
            GUIDs.
          </li>
          <li>
            Even with read-only permissions, your organization may have policies
            governing API access.{" "}
            <strong>
              Validate with your security team before enabling in production.
            </strong>
          </li>
          <li>
            Uses the Microsoft Graph PowerShell public client ID — no app
            registration required.
          </li>
          <li>
            Requests only these delegated read permissions (admin consent may be
            needed on first use):
            <ul style={{ margin: "2px 0 0", paddingLeft: "16px" }}>
              {GRAPH_CAPABILITY_ROWS.map(([, , scope]) => (
                <li key={scope}>
                  <code>{scope}</code>
                </li>
              ))}
            </ul>
          </li>
        </ul>
      </div>

      {/* Enable toggle */}
      <div style={{ display: "flex", flexDirection: "column", gap: "12px" }}>
        <label
          style={{
            display: "flex",
            alignItems: "flex-start",
            gap: "8px",
            fontSize: "12px",
            color: tokens.colorNeutralForeground1,
            cursor: "pointer",
          }}
        >
          <input
            type="checkbox"
            checked={graphApiEnabled}
            onChange={(e) => handleToggle(e.target.checked)}
            style={{ marginTop: "2px", cursor: "pointer" }}
          />
          <div>
            <div style={{ fontWeight: 600 }}>
              Enable Graph API GUID resolution
            </div>
            <div
              style={{
                fontSize: "11px",
                color: tokens.colorNeutralForeground3,
                marginTop: "2px",
              }}
            >
              When enabled, Intune app GUIDs in logs can be resolved to display
              names via Microsoft Graph.
            </div>
          </div>
        </label>

        {/* Confirmation dialog when enabling */}
        {showConfirmEnable && (
          <div
            style={{
              padding: "12px",
              borderRadius: "4px",
              backgroundColor: tokens.colorNeutralBackground3,
              border: `1px solid ${tokens.colorNeutralStroke1}`,
              fontSize: "12px",
            }}
          >
            <div style={{ fontWeight: 600, marginBottom: "8px" }}>
              Confirm: Enable Graph API connection
            </div>
            <div
              style={{
                marginBottom: "10px",
                lineHeight: 1.5,
                color: tokens.colorNeutralForeground2,
              }}
            >
              You are about to enable network calls to Microsoft Graph API.
              CMTrace Open will authenticate using your current Windows session
              and make read-only API calls to your Intune tenant. No data is
              sent to third parties.
            </div>
            <div style={{ display: "flex", gap: "8px" }}>
              <button
                type="button"
                onClick={confirmEnable}
                style={{
                  padding: "4px 12px",
                  fontSize: "12px",
                  border: `1px solid ${tokens.colorBrandStroke1}`,
                  backgroundColor: tokens.colorBrandBackground,
                  color: tokens.colorNeutralForegroundOnBrand,
                  borderRadius: "4px",
                  cursor: "pointer",
                }}
              >
                I understand, enable it
              </button>
              <button
                type="button"
                onClick={() => setShowConfirmEnable(false)}
                style={{
                  padding: "4px 12px",
                  fontSize: "12px",
                  border: `1px solid ${tokens.colorNeutralStroke1}`,
                  backgroundColor: "transparent",
                  color: tokens.colorNeutralForeground1,
                  borderRadius: "4px",
                  cursor: "pointer",
                }}
              >
                Cancel
              </button>
            </div>
          </div>
        )}

        {/* Auth status & sign-in (only when enabled) */}
        {graphApiEnabled && (
          <div
            style={{
              padding: "10px 12px",
              borderRadius: "4px",
              backgroundColor: tokens.colorNeutralBackground3,
              fontSize: "12px",
            }}
          >
            <div
              style={{
                fontWeight: 600,
                marginBottom: "8px",
                fontSize: "12px",
              }}
            >
              Connection Status
            </div>

            {displayedAuthStatus?.isAuthenticated ? (
              <div>
                <div
                  style={{
                    display: "flex",
                    alignItems: "center",
                    gap: "6px",
                    marginBottom: "6px",
                  }}
                >
                  <span
                    style={{
                      width: "8px",
                      height: "8px",
                      borderRadius: "50%",
                      backgroundColor: tokens.colorPaletteGreenBackground3,
                      display: "inline-block",
                    }}
                  />
                  <span>
                    {displayedAuthStatus.missingScopes.length > 0
                      ? "Connected with partial permissions"
                      : "Connected"}
                  </span>
                </div>
                {displayedAuthStatus.userPrincipalName && (
                  <div
                    style={{
                      color: tokens.colorNeutralForeground3,
                      marginBottom: "4px",
                    }}
                  >
                    Signed in as: {displayedAuthStatus.userPrincipalName}
                  </div>
                )}
                {displayedAuthStatus.tenantId && (
                  <div
                    style={{
                      color: tokens.colorNeutralForeground3,
                      marginBottom: "8px",
                      fontFamily: "monospace",
                      fontSize: "11px",
                    }}
                  >
                    Tenant: {displayedAuthStatus.tenantId}
                  </div>
                )}
                <div
                  aria-label="Graph delegated capabilities"
                  style={{
                    display: "grid",
                    gap: "4px",
                    marginBottom: "8px",
                    color: tokens.colorNeutralForeground2,
                    fontSize: "11px",
                  }}
                >
                  {GRAPH_CAPABILITY_ROWS.map(([label, capability, scope]) => {
                    const available =
                      displayedAuthStatus.capabilities[capability];
                    return (
                      <div key={scope}>
                        <span
                          style={{
                            color: available
                              ? tokens.colorPaletteGreenForeground1
                              : tokens.colorPaletteYellowForeground2,
                            fontWeight: 600,
                          }}
                        >
                          {label} ·{" "}
                          {available ? "Available" : "Missing permission"}
                        </span>
                        {!available && (
                          <span style={{ fontFamily: "monospace" }}>
                            {` — ${scope}`}
                          </span>
                        )}
                      </div>
                    );
                  })}
                </div>
                <div
                  style={{
                    display: "flex",
                    alignItems: "center",
                    flexWrap: "wrap",
                    gap: "8px",
                    marginBottom: cachedAppCount != null ? "8px" : "0",
                  }}
                >
                  {displayedAuthStatus.missingScopes.length > 0 && (
                    <button
                      type="button"
                      onClick={handleRequestMissingPermissions}
                      disabled={graphActionBusy}
                      style={{
                        padding: "4px 12px",
                        fontSize: "12px",
                        border: `1px solid ${tokens.colorBrandStroke1}`,
                        backgroundColor: tokens.colorBrandBackground,
                        color: tokens.colorNeutralForegroundOnBrand,
                        borderRadius: "4px",
                        cursor: permissionsLoading
                          ? "wait"
                          : graphActionBusy
                            ? "not-allowed"
                            : "pointer",
                        opacity: graphActionBusy ? 0.7 : 1,
                      }}
                    >
                      {permissionsLoading
                        ? "Requesting permissions..."
                        : "Request missing permissions"}
                    </button>
                  )}
                  <button
                    type="button"
                    onClick={handlePrePopulateCache}
                    disabled={
                      graphActionBusy || !displayedAuthStatus.capabilities.apps
                    }
                    style={{
                      padding: "4px 12px",
                      fontSize: "12px",
                      border: `1px solid ${tokens.colorNeutralStroke1}`,
                      backgroundColor: "transparent",
                      color: tokens.colorNeutralForeground2,
                      borderRadius: "4px",
                      cursor: cacheLoading
                        ? "wait"
                        : graphActionBusy ||
                            !displayedAuthStatus.capabilities.apps
                          ? "not-allowed"
                          : "pointer",
                      opacity:
                        graphActionBusy ||
                        !displayedAuthStatus.capabilities.apps
                          ? 0.7
                          : 1,
                    }}
                  >
                    {cacheLoading
                      ? "Fetching apps..."
                      : "Pre-populate app cache"}
                  </button>
                  <button
                    type="button"
                    onClick={handleSignOut}
                    disabled={graphActionBusy}
                    style={{
                      padding: "4px 12px",
                      fontSize: "12px",
                      border: `1px solid ${tokens.colorNeutralStroke1}`,
                      backgroundColor: "transparent",
                      color: tokens.colorNeutralForeground2,
                      borderRadius: "4px",
                      cursor: graphActionBusy ? "not-allowed" : "pointer",
                      opacity: graphActionBusy ? 0.7 : 1,
                    }}
                  >
                    Sign out
                  </button>
                </div>
                {!displayedAuthStatus.capabilities.apps && (
                  <div
                    style={{
                      fontSize: "11px",
                      color: tokens.colorPaletteYellowForeground2,
                      marginTop: "6px",
                    }}
                  >
                    App cache requires DeviceManagementApps.Read.All.
                  </div>
                )}
                {cachedAppCount != null && (
                  <div
                    style={{
                      fontSize: "11px",
                      color:
                        cachedAppCount > 0
                          ? tokens.colorPaletteGreenForeground1
                          : tokens.colorNeutralForeground3,
                    }}
                  >
                    {cachedAppCount > 0
                      ? `Cached ${cachedAppCount} app${cachedAppCount !== 1 ? "s" : ""} from Intune. GUIDs will be resolved automatically during log analysis.`
                      : "No apps returned from Graph API. Check permissions."}
                  </div>
                )}
                {cacheError && (
                  <div
                    style={{
                      fontSize: "11px",
                      color: tokens.colorPaletteRedForeground1,
                      marginTop: "4px",
                    }}
                  >
                    {cacheError}
                  </div>
                )}
              </div>
            ) : (
              <div>
                <div
                  style={{
                    display: "flex",
                    alignItems: "center",
                    gap: "6px",
                    marginBottom: "8px",
                  }}
                >
                  <span
                    style={{
                      width: "8px",
                      height: "8px",
                      borderRadius: "50%",
                      backgroundColor: tokens.colorNeutralForeground3,
                      display: "inline-block",
                    }}
                  />
                  <span>Not connected</span>
                </div>
                {displayedAuthStatus?.error && (
                  <div
                    style={{
                      color: tokens.colorPaletteRedForeground1,
                      marginBottom: "8px",
                      fontSize: "11px",
                    }}
                  >
                    {displayedAuthStatus.error}
                  </div>
                )}
                <button
                  type="button"
                  onClick={handleSignIn}
                  disabled={graphActionBusy}
                  style={{
                    padding: "4px 12px",
                    fontSize: "12px",
                    border: `1px solid ${tokens.colorBrandStroke1}`,
                    backgroundColor: tokens.colorBrandBackground,
                    color: tokens.colorNeutralForegroundOnBrand,
                    borderRadius: "4px",
                    cursor: loading ? "wait" : "pointer",
                    opacity: loading ? 0.7 : 1,
                  }}
                >
                  {loading ? "Signing in..." : "Sign in with Windows"}
                </button>
              </div>
            )}
            {permissionNotice && (
              <div
                role={permissionNotice.tone === "error" ? "alert" : "status"}
                aria-label={permissionNotice.message}
                style={{
                  marginTop: "8px",
                  padding: "7px 9px",
                  borderRadius: "4px",
                  border: `1px solid ${
                    permissionNotice.tone === "success"
                      ? tokens.colorPaletteGreenBorder1
                      : permissionNotice.tone === "warning"
                        ? tokens.colorPaletteYellowBorder1
                        : tokens.colorPaletteRedBorder1
                  }`,
                  backgroundColor:
                    permissionNotice.tone === "success"
                      ? tokens.colorPaletteGreenBackground1
                      : permissionNotice.tone === "warning"
                        ? tokens.colorPaletteYellowBackground1
                        : tokens.colorPaletteRedBackground1,
                  color:
                    permissionNotice.tone === "success"
                      ? tokens.colorPaletteGreenForeground1
                      : permissionNotice.tone === "warning"
                        ? tokens.colorPaletteYellowForeground2
                        : tokens.colorPaletteRedForeground1,
                  fontSize: "11px",
                  lineHeight: 1.5,
                }}
              >
                {permissionNotice.message}
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}
