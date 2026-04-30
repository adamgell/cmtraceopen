import { MessageBar, MessageBarBody, MessageBarTitle } from "@fluentui/react-components";
import type { JamfEnvironment } from "./types";

interface Props {
  environment: JamfEnvironment | null;
  loading: boolean;
}

export function MacosJamfEnvironmentBanner({ environment, loading }: Props) {
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
