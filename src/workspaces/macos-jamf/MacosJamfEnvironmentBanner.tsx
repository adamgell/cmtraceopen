import { Button, MessageBar, MessageBarActions, MessageBarBody, MessageBarTitle } from "@fluentui/react-components";
import type { JamfEnvironment } from "./types";

interface Props {
  environment: JamfEnvironment | null;
  loading: boolean;
  error?: string | null;
  onRetry?: () => void;
}

export function MacosJamfEnvironmentBanner({ environment, loading, error, onRetry }: Props) {
  // A failed detection must not masquerade as "still scanning" — without this
  // branch an errored environment slice renders the info banner forever.
  if (error) {
    return (
      <MessageBar intent="error">
        <MessageBarBody>
          <MessageBarTitle>Unable to detect JAMF</MessageBarTitle>
          {error}
        </MessageBarBody>
        {onRetry && (
          <MessageBarActions>
            <Button size="small" onClick={onRetry}>Retry</Button>
          </MessageBarActions>
        )}
      </MessageBar>
    );
  }
  if (loading || !environment) {
    return (
      <MessageBar intent="info">
        <MessageBarBody>
          <MessageBarTitle>Detecting JAMF</MessageBarTitle>
          Scanning for JAMF binary, JSS configuration, and JAMF Connect...
        </MessageBarBody>
      </MessageBar>
    );
  }
  if (!environment.jamfInstalled) {
    return (
      <MessageBar intent="warning">
        <MessageBarBody>
          <MessageBarTitle>JAMF not detected</MessageBarTitle>
          {environment.summary}
        </MessageBarBody>
      </MessageBar>
    );
  }
  return (
    <MessageBar intent="success">
      <MessageBarBody>
        <MessageBarTitle>JAMF detected</MessageBarTitle>
        {environment.summary}
      </MessageBarBody>
    </MessageBar>
  );
}
