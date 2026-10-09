import {
  Button,
  Menu,
  MenuItem,
  MenuList,
  MenuPopover,
  MenuTrigger,
  SplitButton,
  tokens,
} from "@fluentui/react-components";
import {
  Camera16Regular,
  ChevronDown12Regular,
  ClipboardPaste16Regular,
  DocumentText16Regular,
  FolderOpen16Regular,
} from "@fluentui/react-icons";
import { useAppActions } from "../../hooks/use-app-actions";
import { getLogListMetrics } from "../../lib/log-accessibility";
import { useUiStore } from "../../stores/ui-store";
import { useDsregcmdStore } from "./dsregcmd-store";

/** Runs a load action, logging instead of leaving a rejected promise unhandled. */
function run(label: string, action: () => Promise<void>) {
  void action().catch((error) => {
    console.error(`[dsregcmd-toolbar] ${label} failed`, error);
  });
}

export function DsregcmdToolbarAction() {
  const isAnalyzing = useDsregcmdStore((s) => s.isAnalyzing);
  const logListFontSize = useUiStore((s) => s.logListFontSize);
  const {
    openSourceFileDialog,
    openSourceFolderDialog,
    pasteDsregcmdSource,
    captureDsregcmdSource,
  } = useAppActions();

  const capture = () => run("capture", captureDsregcmdSource);
  const paste = () => run("paste", pasteDsregcmdSource);
  const openFile = () => run("open file", openSourceFileDialog);
  const openFolder = () => run("open folder", openSourceFolderDialog);

  const linkFontSize = Math.max(
    10,
    getLogListMetrics(logListFontSize).fontSize - 2,
  );
  const linkStyle = {
    fontSize: linkFontSize,
    minWidth: 0,
  };

  return (
    <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
      <Menu positioning="below-end">
        <MenuTrigger disableButtonEnhancement>
          {(triggerProps) => (
            <SplitButton
              appearance="primary"
              size="small"
              disabled={isAnalyzing}
              menuButton={{
                ...triggerProps,
                "aria-label": "More capture options",
              }}
              primaryActionButton={{ onClick: capture }}
              icon={<Camera16Regular />}
              menuIcon={<ChevronDown12Regular />}
            >
              Capture now
            </SplitButton>
          )}
        </MenuTrigger>
        <MenuPopover>
          <MenuList>
            <MenuItem icon={<ClipboardPaste16Regular />} onClick={paste}>
              Paste
            </MenuItem>
            <MenuItem icon={<DocumentText16Regular />} onClick={openFile}>
              Open text file...
            </MenuItem>
            <MenuItem icon={<FolderOpen16Regular />} onClick={openFolder}>
              Open evidence folder...
            </MenuItem>
          </MenuList>
        </MenuPopover>
      </Menu>
      <span
        style={{
          display: "inline-flex",
          alignItems: "center",
          gap: 2,
          color: tokens.colorNeutralForeground3,
          fontSize: linkFontSize,
        }}
      >
        <span aria-hidden="true">or</span>
        <Button
          appearance="subtle"
          size="small"
          disabled={isAnalyzing}
          style={linkStyle}
          onClick={paste}
        >
          Paste
        </Button>
        <span aria-hidden="true">&middot;</span>
        <Button
          appearance="subtle"
          size="small"
          disabled={isAnalyzing}
          style={linkStyle}
          onClick={openFile}
        >
          Open file...
        </Button>
        <span aria-hidden="true">&middot;</span>
        <Button
          appearance="subtle"
          size="small"
          disabled={isAnalyzing}
          style={linkStyle}
          onClick={openFolder}
        >
          Open folder...
        </Button>
      </span>
    </div>
  );
}
