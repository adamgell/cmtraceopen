import React from "react";
import ReactDOM from "react-dom/client";
import App from "./App";
import { useAppMenu } from "./hooks/use-app-menu";

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
  }
  button {
    font-size: 12px;
    padding: 2px 8px;
    cursor: pointer;
    border: 1px solid #999;
    background: #e8e8e8;
    border-radius: 2px;
  }
  button:hover {
    background: #d0d0d0;
  }
  button:active {
    background: #c0c0c0;
  }
  input {
    border: 1px solid #999;
    border-radius: 2px;
  }
  mark {
    padding: 0;
  }
`;
document.head.appendChild(style);

ReactDOM.createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <AppRoot />
  </React.StrictMode>
);