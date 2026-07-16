import { useState, useEffect, useCallback } from "react";
import { tokens } from "@fluentui/react-components";
import { useUiStore } from "../../../stores/ui-store";
import {
  graphAuthenticate,
  graphGetAuthStatus,
  graphSignOut,
  graphFetchAllApps,
  type GraphAuthStatus,
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

export function GraphApiTab() {
  const graphApiEnabled = useUiStore((state) => state.graphApiEnabled);
  const setGraphApiEnabled = useUiStore((state) => state.setGraphApiEnabled);
  const currentPlatform = useUiStore((state) => state.currentPlatform);

  const [authStatus, setAuthStatus] = useState<GraphAuthStatus | null>(null);
  const [loading, setLoading] = useState(false);
  const [cacheLoading, setCacheLoading] = useState(false);
  const [cachedAppCount, setCachedAppCount] = useState<number | null>(null);
  const [cacheError, setCacheError] = useState<string | null>(null);
  const [showConfirmEnable, setShowConfirmEnable] = useState(false);

  const refreshStatus = useCallback(async () => {
    if (!graphApiEnabled) return;
    try {
      const status = await graphGetAuthStatus();
      setAuthStatus(status);
    } catch {
      // Command may not exist on non-Windows
    }
  }, [graphApiEnabled]);

  useEffect(() => {
    refreshStatus();
  }, [refreshStatus]);

  const handleToggle = (checked: boolean) => {
    if (checked) {
      setShowConfirmEnable(true);
    } else {
      setGraphApiEnabled(false);
      setAuthStatus(null);
      useUiStore.getState().setGraphApiStatus("idle");
    }
  };

  const confirmEnable = () => {
    setGraphApiEnabled(true);
    setShowConfirmEnable(false);
  };

  const handleSignIn = async () => {
    setLoading(true);
    useUiStore.getState().setGraphApiStatus("connecting");
    try {
      const status = await graphAuthenticate();
      setAuthStatus(status);
      useUiStore
        .getState()
        .setGraphApiStatus(status.isAuthenticated ? "connected" : "error");
    } catch (e) {
      useUiStore.getState().setGraphApiStatus("error");
      setAuthStatus({
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
      });
    } finally {
      setLoading(false);
    }
  };

  const handleSignOut = async () => {
    try {
      await graphSignOut();
      setAuthStatus(null);
      setCachedAppCount(null);
      useUiStore.getState().setGraphApiStatus("idle");
    } catch {
      // ignore
    }
  };

  const handlePrePopulateCache = async () => {
    setCacheLoading(true);
    setCacheError(null);
    setCachedAppCount(null);
    try {
      const apps = await graphFetchAllApps();
      setCachedAppCount(apps.length);

      if (apps.length > 0) {
        useIntuneStore
          .getState()
          .mergeGuidRegistry(buildGraphRegistryEntries(apps));
      }
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      setCacheError(msg);
    } finally {
      setCacheLoading(false);
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

            {authStatus?.isAuthenticated ? (
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
                    {authStatus.missingScopes.length > 0
                      ? "Connected with partial permissions"
                      : "Connected"}
                  </span>
                </div>
                {authStatus.userPrincipalName && (
                  <div
                    style={{
                      color: tokens.colorNeutralForeground3,
                      marginBottom: "4px",
                    }}
                  >
                    Signed in as: {authStatus.userPrincipalName}
                  </div>
                )}
                {authStatus.tenantId && (
                  <div
                    style={{
                      color: tokens.colorNeutralForeground3,
                      marginBottom: "8px",
                      fontFamily: "monospace",
                      fontSize: "11px",
                    }}
                  >
                    Tenant: {authStatus.tenantId}
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
                    const available = authStatus.capabilities[capability];
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
                    gap: "8px",
                    marginBottom: cachedAppCount != null ? "8px" : "0",
                  }}
                >
                  <button
                    type="button"
                    onClick={handlePrePopulateCache}
                    disabled={cacheLoading || !authStatus.capabilities.apps}
                    style={{
                      padding: "4px 12px",
                      fontSize: "12px",
                      border: `1px solid ${tokens.colorBrandStroke1}`,
                      backgroundColor: tokens.colorBrandBackground,
                      color: tokens.colorNeutralForegroundOnBrand,
                      borderRadius: "4px",
                      cursor: cacheLoading
                        ? "wait"
                        : authStatus.capabilities.apps
                          ? "pointer"
                          : "not-allowed",
                      opacity:
                        cacheLoading || !authStatus.capabilities.apps ? 0.7 : 1,
                    }}
                  >
                    {cacheLoading
                      ? "Fetching apps..."
                      : "Pre-populate app cache"}
                  </button>
                  <button
                    type="button"
                    onClick={handleSignOut}
                    style={{
                      padding: "4px 12px",
                      fontSize: "12px",
                      border: `1px solid ${tokens.colorNeutralStroke1}`,
                      backgroundColor: "transparent",
                      color: tokens.colorNeutralForeground2,
                      borderRadius: "4px",
                      cursor: "pointer",
                    }}
                  >
                    Sign out
                  </button>
                </div>
                {!authStatus.capabilities.apps && (
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
                {authStatus?.error && (
                  <div
                    style={{
                      color: tokens.colorPaletteRedForeground1,
                      marginBottom: "8px",
                      fontSize: "11px",
                    }}
                  >
                    {authStatus.error}
                  </div>
                )}
                <button
                  type="button"
                  onClick={handleSignIn}
                  disabled={loading}
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
          </div>
        )}
      </div>
    </div>
  );
}
