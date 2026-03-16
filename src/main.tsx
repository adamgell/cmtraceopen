import React from "react";
import ReactDOM from "react-dom/client";
import { FluentProvider } from "@fluentui/react-components";
import App from "./App";
import { useAppMenu } from "./hooks/use-app-menu";
import { cmtraceFluentTheme } from "./lib/fluent-theme";
import { initializeDateTimeFormatting } from "./lib/date-time-format";

const RootWrapper = import.meta.env.DEV ? React.Fragment : React.StrictMode;

function AppRoot() {
  useAppMenu();
  return <App />;
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
    background: #f4f7fb;
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
      <FluentProvider theme={cmtraceFluentTheme} style={{ height: "100%" }}>
        <AppRoot />
      </FluentProvider>
    </RootWrapper>
  );
}

void bootstrap();