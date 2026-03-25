import { useEffect, useRef } from "react";
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
import { useLogStore } from "../../stores/log-store";

interface FindBarProps {
  onClose: () => void;
}

export function FindBar({ onClose }: FindBarProps) {
  const inputRef = useRef<HTMLInputElement>(null);

  const findQuery = useLogStore((s) => s.findQuery);
  const findCaseSensitive = useLogStore((s) => s.findCaseSensitive);
  const findUseRegex = useLogStore((s) => s.findUseRegex);
  const findRegexError = useLogStore((s) => s.findRegexError);
  const findMatchIds = useLogStore((s) => s.findMatchIds);
  const findCurrentIndex = useLogStore((s) => s.findCurrentIndex);
  const setFindQuery = useLogStore((s) => s.setFindQuery);
  const setFindCaseSensitive = useLogStore((s) => s.setFindCaseSensitive);
  const setFindUseRegex = useLogStore((s) => s.setFindUseRegex);
  const findNext = useLogStore((s) => s.findNext);
  const findPrevious = useLogStore((s) => s.findPrevious);

  // Auto-focus on mount
  useEffect(() => {
    if (inputRef.current) {
      inputRef.current.focus();
      inputRef.current.select();
    }
  }, []);

  const handleKeyDown = (event: React.KeyboardEvent) => {
    if (event.key === "Escape") {
      event.preventDefault();
      onClose();
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
        placeholder="Find..."
        size="small"
        style={{ minWidth: 200, maxWidth: 300, flex: 1 }}
        contentAfter={
          hasQuery ? (
            <span
              style={{
                fontSize: 11,
                color: matchCount === 0 && !findRegexError
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

      <Tooltip content="Match Case" relationship="label">
        <Button
          appearance="subtle"
          size="small"
          style={toggleButtonStyle(findCaseSensitive)}
          onClick={() => setFindCaseSensitive(!findCaseSensitive)}
          aria-label="Match case"
          aria-pressed={findCaseSensitive}
        >
          <TextCaseTitleRegular fontSize={16} />
        </Button>
      </Tooltip>

      <Tooltip content="Use Regular Expression" relationship="label">
        <Button
          appearance="subtle"
          size="small"
          style={toggleButtonStyle(findUseRegex)}
          onClick={() => setFindUseRegex(!findUseRegex)}
          aria-label="Use regular expression"
          aria-pressed={findUseRegex}
        >
          <span style={{ fontSize: 13, fontFamily: "monospace", fontWeight: 600 }}>.*</span>
        </Button>
      </Tooltip>

      <div style={{ width: 1, height: 20, backgroundColor: tokens.colorNeutralStroke2 }} />

      <Tooltip content="Previous Match (Shift+Enter)" relationship="label">
        <Button
          appearance="subtle"
          size="small"
          icon={<ArrowUpRegular />}
          disabled={matchCount === 0}
          onClick={() => findPrevious("find-bar.button")}
          aria-label="Previous match"
          style={{ minWidth: 28, width: 28, height: 28, padding: 0 }}
        />
      </Tooltip>

      <Tooltip content="Next Match (Enter)" relationship="label">
        <Button
          appearance="subtle"
          size="small"
          icon={<ArrowDownRegular />}
          disabled={matchCount === 0}
          onClick={() => findNext("find-bar.button")}
          aria-label="Next match"
          style={{ minWidth: 28, width: 28, height: 28, padding: 0 }}
        />
      </Tooltip>

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
