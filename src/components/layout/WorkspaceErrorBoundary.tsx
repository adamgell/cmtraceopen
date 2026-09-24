import { Component, type ErrorInfo, type ReactNode } from "react";

interface Props {
  /** Workspace id, used in the message so a report names the failing surface. */
  workspaceId: string;
  children: ReactNode;
}

interface State {
  error: Error | null;
}

/**
 * Containment for a workspace that throws while rendering.
 *
 * Without this, a throw anywhere beneath the active workspace unmounts the whole
 * tree. That is not a blank page: `main.tsx` dismisses the splash from an effect,
 * so a throw during the first render leaves the splash up indefinitely and the
 * user cannot tell a crash from a slow start.
 *
 * Render only — React boundaries do not catch event handlers, async callbacks or
 * errors thrown in the boundary itself.
 */
export class WorkspaceErrorBoundary extends Component<Props, State> {
  state: State = { error: null };

  static getDerivedStateFromError(error: unknown): State {
    return { error: error instanceof Error ? error : new Error(String(error)) };
  }

  componentDidCatch(error: Error, info: ErrorInfo): void {
    console.error(
      `[workspace] ${this.props.workspaceId} failed to render`,
      error,
      info.componentStack,
    );
  }

  render(): ReactNode {
    const { error } = this.state;
    if (!error) return this.props.children;

    return (
      <div role="alert" data-testid="workspace-error-boundary" style={{ padding: 24 }}>
        <h2 style={{ margin: "0 0 8px", fontSize: 16 }}>
          This workspace could not be displayed
        </h2>
        <p style={{ margin: "0 0 12px" }}>
          The <code>{this.props.workspaceId}</code> workspace stopped while rendering. Other
          workspaces are unaffected — switch to one from the sidebar, or reopen the source.
        </p>
        <pre
          style={{
            margin: 0,
            padding: 8,
            overflow: "auto",
            maxHeight: 160,
            fontSize: 12,
            whiteSpace: "pre-wrap",
          }}
        >
          {error.message}
        </pre>
      </div>
    );
  }
}
