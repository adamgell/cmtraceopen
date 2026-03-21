import React, { useEffect } from "react";
import ReactDOM from "react-dom/client";
import { FluentProvider } from "@fluentui/react-components";
import App from "./App";
import { useAppMenu } from "./hooks/use-app-menu";
import { getThemeById } from "./lib/themes";
import { useUiStore } from "./stores/ui-store";
import { initializeDateTimeFormatting } from "./lib/date-time-format";

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

  return <App />;
}

function ThemedApp() {
  const themeId = useUiStore((s) => s.themeId);
  const activeTheme = getThemeById(themeId);

  useEffect(() => {
    document.documentElement.style.setProperty("color-scheme", activeTheme.colorScheme);
    document.body.style.background = activeTheme.fluentTheme.colorNeutralBackground1 as string;
  }, [activeTheme]);

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
    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
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