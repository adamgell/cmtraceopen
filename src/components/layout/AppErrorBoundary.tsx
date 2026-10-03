import { Component, type ErrorInfo, type ReactNode } from "react";

interface Props {
  children: ReactNode;
  onError: () => void;
}

/** Last-resort fallback, independent of the theme and application shell. */
export class AppErrorBoundary extends Component<Props, { error: Error | null }> {
  state: { error: Error | null } = { error: null };

  static getDerivedStateFromError(error: unknown) {
    return { error: error instanceof Error ? error : new Error(String(error)) };
  }

  componentDidCatch(error: Error, info: ErrorInfo) {
    console.error("[application] failed to render", error, info.componentStack);
    this.props.onError();
  }

  render(): ReactNode {
    if (!this.state.error) return this.props.children;
    return (
      <div role="alert" style={{ padding: 24, overflow: "auto", height: "100%" }}>
        <h1>CMTrace Open could not be displayed</h1>
        <p>Reload the application to try again. Unsaved work may be lost.</p>
        <button type="button" onClick={() => window.location.reload()}>
          Reload application
        </button>
        <pre style={{ whiteSpace: "pre-wrap" }}>{this.state.error.message}</pre>
      </div>
    );
  }
}
