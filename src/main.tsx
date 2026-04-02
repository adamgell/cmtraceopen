import React, { useEffect } from "react";
import ReactDOM from "react-dom/client";
import { FluentProvider } from "@fluentui/react-components";
import App from "./App";
import { useAppMenu } from "./hooks/use-app-menu";
import { getThemeById } from "./lib/themes";
import { useUiStore } from "./stores/ui-store";
import { initializeDateTimeFormatting, refreshDateTimeFormatting } from "./lib/date-time-format";
import { getCurrentWindow } from "@tauri-apps/api/window";
// Register Graph API auto-connect (runs after persist hydration)
import "./hooks/use-graph-api-startup";

const RootWrapper = import.meta.env.DEV ? React.Fragment : React.StrictMode;

function dismissSplash() {
  const splash = document.getElementById("splash");
  if (splash) {
    splash.classList.add("fade-out");
    setTimeout(() => splash.remove(), 500);
  }
}

function AppRoot() {
  useAppMenu();

  useEffect(() => {
    // Dismiss splash screen once the app has mounted
    dismissSplash();
  }, []);

  useEffect(() => {
    let unlisten: (() => void) | undefined;
    getCurrentWindow()
      .onFocusChanged(({ payload: focused }) => {
        if (focused) void refreshDateTimeFormatting();
      })
      .then((fn) => {
        unlisten = fn;
      });
    return () => unlisten?.();
  }, []);

  return <App />;
}

function ThemedApp() {
  const themeId = useUiStore((s) => s.themeId);
  const fontFamily = useUiStore((s) => s.fontFamily);
  const activeTheme = getThemeById(themeId);

  useEffect(() => {
    document.documentElement.style.setProperty("color-scheme", activeTheme.colorScheme);
    document.body.style.background = activeTheme.fluentTheme.colorNeutralBackground1 as string;
  }, [activeTheme]);

  useEffect(() => {
    const root = document.documentElement;
    if (fontFamily) {
      const quoted = `'${fontFamily}'`;
      root.style.setProperty(
        "--cmtrace-font-family-ui",
        `${quoted}, 'Segoe UI', Tahoma, sans-serif`
      );
      root.style.setProperty(
        "--cmtrace-font-family-mono",
        `${quoted}, Consolas, 'Cascadia Mono', 'Courier New', monospace`
      );
    } else {
      root.style.removeProperty("--cmtrace-font-family-ui");
      root.style.removeProperty("--cmtrace-font-family-mono");
    }
  }, [fontFamily]);

  return (
    <FluentProvider theme={activeTheme.fluentTheme} style={{ height: "100%" }}>
      <AppRoot />
    </FluentProvider>
  );
}

// Reset default browser styles for a desktop-app feel
const style = document.createElement("style");
style.textContent = `
  * {
    margin: 0;
    padding: 0;
    box-sizing: border-box;
  }
  html, body, #root {
    height: 100%;
    overflow: hidden;
    font-family: var(--cmtrace-font-family-ui, 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif);
    font-size: 13px;
  }
  mark {
    padding: 0;
  }
`;
document.head.appendChild(style);

async function bootstrap() {
  await initializeDateTimeFormatting();

  ReactDOM.createRoot(document.getElementById("root")!).render(
    <RootWrapper>
      <ThemedApp />
    </RootWrapper>
  );
}

void bootstrap();