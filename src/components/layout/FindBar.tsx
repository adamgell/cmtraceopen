import { useEffect, useRef, type KeyboardEvent, type ReactNode } from "react";
import {
  Button,
  Input,
  tokens,
  Tooltip,
} from "@fluentui/react-components";
import {
  DismissRegular,
  ArrowUpRegular,
  ArrowDownRegular,
  TextCaseTitleRegular,
} from "@fluentui/react-icons";
import { isLargeFileModeActive, useLogStore } from "../../stores/log-store";

interface FindBarProps {
  onClose: () => void;
}

const LARGE_FILE_MODE_FIND_MESSAGE =
  "Find is disabled in large-file mode to keep the app responsive.";

function TooltipButton({ content, children }: { content: string; children: ReactNode }) {
  return (
    <Tooltip content={content} relationship="label">
      <span style={{ display: "inline-flex" }}>{children}</span>
    </Tooltip>
  );
}

export function FindBar({ onClose }: FindBarProps) {
  const inputRef = useRef<HTMLInputElement>(null);

  const findQuery = useLogStore((s) => s.findQuery);
  const findCaseSensitive = useLogStore((s) => s.findCaseSensitive);
  const findUseRegex = useLogStore((s) => s.findUseRegex);
  const findRegexError = useLogStore((s) => s.findRegexError);
  const findMatchIds = useLogStore((s) => s.findMatchIds);
  const findCurrentIndex = useLogStore((s) => s.findCurrentIndex);
  const largeFileModeActive = useLogStore((s) => isLargeFileModeActive(s.largeFileMode));
  const setFindQuery = useLogStore((s) => s.setFindQuery);
  const setFindCaseSensitive = useLogStore((s) => s.setFindCaseSensitive);
  const setFindUseRegex = useLogStore((s) => s.setFindUseRegex);
  const findNext = useLogStore((s) => s.findNext);
  const findPrevious = useLogStore((s) => s.findPrevious);

  useEffect(() => {
    if (largeFileModeActive || !inputRef.current) {
      return;
    }

    inputRef.current.focus();
    inputRef.current.select();
  }, [largeFileModeActive]);

  const handleKeyDown = (event: KeyboardEvent) => {
    if (event.key === "Escape") {
      event.preventDefault();
      onClose();
      return;
    }

    if (largeFileModeActive) {
      return;
    }

    if (event.key === "Enter" || event.key === "F3") {
      event.preventDefault();
      event.stopPropagation();
      if (event.shiftKey) {
        findPrevious("find-bar.keyboard");
      } else {
        findNext("find-bar.keyboard");
      }
    }
  };

  const matchCount = findMatchIds.length;
  const hasQuery = findQuery.trim().length > 0;

  let statusText = "";
  if (hasQuery && findRegexError) {
    statusText = "Invalid regex";
  } else if (hasQuery && matchCount === 0) {
    statusText = "No results";
  } else if (hasQuery && matchCount > 0) {
    statusText = `${findCurrentIndex + 1} of ${matchCount}`;
  }

  const toggleButtonStyle = (active: boolean) => ({
    minWidth: 28,
    width: 28,
    height: 28,
    padding: 0,
    borderRadius: 4,
    backgroundColor: active ? tokens.colorBrandBackground : "transparent",
    color: active ? tokens.colorNeutralForegroundOnBrand : tokens.colorNeutralForeground2,
    border: active ? "none" : `1px solid ${tokens.colorNeutralStroke1}`,
  });

  const matchCaseTooltip = largeFileModeActive
    ? LARGE_FILE_MODE_FIND_MESSAGE
    : "Match case";
  const regexTooltip = largeFileModeActive
    ? LARGE_FILE_MODE_FIND_MESSAGE
    : "Use regular expression";
  const previousTooltip = largeFileModeActive
    ? LARGE_FILE_MODE_FIND_MESSAGE
    : "Previous match (Shift+Enter)";
  const nextTooltip = largeFileModeActive
    ? LARGE_FILE_MODE_FIND_MESSAGE
    : "Next match (Enter)";

  return (
    <div
      style={{
        display: "flex",
        alignItems: "center",
        gap: 4,
        padding: "4px 8px",
        backgroundColor: tokens.colorNeutralBackground3,
        borderBottom: `1px solid ${tokens.colorNeutralStroke2}`,
        minHeight: 36,
        flexShrink: 0,
      }}
    >
      <Input
        ref={inputRef}
        value={findQuery}
        onChange={(_, data) => setFindQuery(data.value)}
        onKeyDown={handleKeyDown}
        placeholder={largeFileModeActive ? "Find unavailable in large-file mode" : "Find..."}
        disabled={largeFileModeActive}
        size="small"
        style={{ minWidth: 200, maxWidth: 300, flex: 1 }}
        contentAfter={
          hasQuery && !largeFileModeActive ? (
            <span
              style={{
                fontSize: 11,
                color: findRegexError || matchCount === 0
                  ? tokens.colorPaletteRedForeground1
                  : tokens.colorNeutralForeground3,
                whiteSpace: "nowrap",
                paddingRight: 4,
              }}
            >
              {statusText}
            </span>
          ) : undefined
        }
      />

      {largeFileModeActive && (
        <span
          style={{
            fontSize: 11,
            color: tokens.colorNeutralForeground3,
            whiteSpace: "nowrap",
          }}
        >
          {LARGE_FILE_MODE_FIND_MESSAGE}
        </span>
      )}

      <TooltipButton content={matchCaseTooltip}>
        <Button
          appearance="subtle"
          size="small"
          style={toggleButtonStyle(findCaseSensitive)}
          onClick={() => setFindCaseSensitive(!findCaseSensitive)}
          aria-label="Match case"
          aria-pressed={findCaseSensitive}
          disabled={largeFileModeActive}
        >
          <TextCaseTitleRegular fontSize={16} />
        </Button>
      </TooltipButton>

      <TooltipButton content={regexTooltip}>
        <Button
          appearance="subtle"
          size="small"
          style={toggleButtonStyle(findUseRegex)}
          onClick={() => setFindUseRegex(!findUseRegex)}
          aria-label="Use regular expression"
          aria-pressed={findUseRegex}
          disabled={largeFileModeActive}
        >
          <span style={{ fontSize: 13, fontFamily: "monospace", fontWeight: 600 }}>.*</span>
        </Button>
      </TooltipButton>

      <div style={{ width: 1, height: 20, backgroundColor: tokens.colorNeutralStroke2 }} />

      <TooltipButton content={previousTooltip}>
        <Button
          appearance="subtle"
          size="small"
          icon={<ArrowUpRegular />}
          disabled={largeFileModeActive || matchCount === 0}
          onClick={() => findPrevious("find-bar.button")}
          aria-label="Previous match"
          style={{ minWidth: 28, width: 28, height: 28, padding: 0 }}
        />
      </TooltipButton>

      <TooltipButton content={nextTooltip}>
        <Button
          appearance="subtle"
          size="small"
          icon={<ArrowDownRegular />}
          disabled={largeFileModeActive || matchCount === 0}
          onClick={() => findNext("find-bar.button")}
          aria-label="Next match"
          style={{ minWidth: 28, width: 28, height: 28, padding: 0 }}
        />
      </TooltipButton>

      <Tooltip content="Close (Escape)" relationship="label">
        <Button
          appearance="subtle"
          size="small"
          icon={<DismissRegular />}
          onClick={onClose}
          aria-label="Close find bar"
          style={{ minWidth: 28, width: 28, height: 28, padding: 0 }}
        />
      </Tooltip>
    </div>
  );
}
