import { useCallback, useEffect, useRef, useState } from "react";
import {
  Badge,
  Button,
  Dialog,
  DialogActions,
  DialogBody,
  DialogContent,
  DialogSurface,
  DialogTitle,
  Input,
  Tooltip,
  tokens,
} from "@fluentui/react-components";
import { CopyRegular, SearchRegular } from "@fluentui/react-icons";
import { invoke } from "@tauri-apps/api/core";
import { writeText } from "@tauri-apps/plugin-clipboard-manager";
import {
  useUiStore,
  type ErrorLookupHistoryEntry,
} from "../../stores/ui-store";
import { LOG_MONOSPACE_FONT_FAMILY } from "../../lib/log-accessibility";

interface ErrorSearchResult {
  codeHex: string;
  codeDecimal: string;
  description: string;
  category: string;
  found: boolean;
}

interface ErrorLookupDialogProps {
  isOpen: boolean;
  onClose: () => void;
}

export function getCategoryColor(
  category: string
):
  | "informative"
  | "warning"
  | "success"
  | "important"
  | "severe"
  | "danger" {
  switch (category) {
    case "Windows":
      return "informative";
    case "Windows Update":
      return "informative";
    case "BITS":
      return "informative";
    case "Intune":
      return "warning";
    case "ConfigMgr":
      return "success";
    case "App Install":
      return "important";
    case "Certificate":
      return "severe";
    case "Security":
      return "danger";
    case "Network":
      return "informative";
    case "Delivery Optimization":
      return "important";
    case "Registry":
      return "informative";
    case "File System":
      return "informative";
    default:
      return "informative";
  }
}

const isCodePattern = (q: string): boolean => {
  const trimmed = q.trim();
  return (
    trimmed.startsWith("0x") ||
    trimmed.startsWith("0X") ||
    trimmed.startsWith("-") ||
    (trimmed.length >= 6 && /^[0-9A-Fa-f]+$/.test(trimmed))
  );
};

export function ErrorLookupDialog({ isOpen, onClose }: ErrorLookupDialogProps) {
  const [query, setQuery] = useState("");
  const [results, setResults] = useState<ErrorSearchResult[]>([]);
  const [isSearching, setIsSearching] = useState(false);
  const [searchError, setSearchError] = useState<string | null>(null);
  const inputRef = useRef<HTMLInputElement>(null);
  const debounceRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const requestIdRef = useRef(0);

  const history = useUiStore((s) => s.errorLookupHistory);
  const addHistoryEntry = useUiStore((s) => s.addErrorLookupHistoryEntry);

  const doSearch = useCallback(
    async (q: string) => {
      if (!q.trim()) {
        setResults([]);
        setSearchError(null);
        setIsSearching(false);
        return;
      }
      const reqId = ++requestIdRef.current;
      setIsSearching(true);
      setSearchError(null);
      try {
        const res = await invoke<ErrorSearchResult[]>("search_error_codes", {
          query: q,
        });
        if (reqId !== requestIdRef.current) return;
        setResults(res);

        // Add to history when search returns exactly one exact match
        if (res.length === 1 && res[0].found) {
          const r = res[0];
          addHistoryEntry({
            codeHex: r.codeHex,
            codeDecimal: r.codeDecimal,
            description: r.description,
            category: r.category,
            found: r.found,
            timestamp: Date.now(),
          });
        }
      } catch (err) {
        if (reqId !== requestIdRef.current) return;
        const message = err instanceof Error ? err.message : String(err);
        setSearchError(message);
      } finally {
        if (reqId === requestIdRef.current) {
          setIsSearching(false);
        }
      }
    },
    [addHistoryEntry]
  );

  // Debounce logic: immediate for code patterns, 300ms for text
  useEffect(() => {
    if (!isOpen) return;

    if (debounceRef.current) {
      clearTimeout(debounceRef.current);
      debounceRef.current = null;
    }

    if (!query.trim()) {
      setResults([]);
      setSearchError(null);
      return;
    }

    if (isCodePattern(query)) {
      void doSearch(query);
    } else {
      debounceRef.current = setTimeout(() => {
        void doSearch(query);
      }, 300);
    }

    return () => {
      if (debounceRef.current) {
        clearTimeout(debounceRef.current);
        debounceRef.current = null;
      }
    };
  }, [query, isOpen, doSearch]);

  // Focus input on open, reset state on close
  useEffect(() => {
    if (isOpen && inputRef.current) {
      inputRef.current.focus();
      inputRef.current.select();
    }

    if (!isOpen) {
      setQuery("");
      setResults([]);
      setIsSearching(false);
      setSearchError(null);
    }
  }, [isOpen]);

  const handleCopy = async (r: ErrorSearchResult | ErrorLookupHistoryEntry) => {
    const text = `${r.codeHex} - ${r.description}`;
    await writeText(text);
  };

  const handleHistoryClick = (h: ErrorLookupHistoryEntry) => {
    setQuery(h.codeHex);
    // No explicit doSearch call needed — the useEffect fires immediately for code patterns
  };

  if (!isOpen) {
    return null;
  }

  return (
    <Dialog
      open={isOpen}
      modalType="modal"
      onOpenChange={(_, data) => {
        if (!data.open) {
          onClose();
        }
      }}
    >
      <DialogSurface
        style={{
          width: "min(560px, calc(100vw - 32px))",
          paddingTop: "8px",
        }}
      >
        <DialogBody>
          <DialogTitle>Error Code Lookup</DialogTitle>
          <DialogContent style={{ display: "grid", gap: "12px" }}>
            <Input
              ref={inputRef}
              value={query}
              onChange={(_, data) => setQuery(data.value)}
              onKeyDown={(e) => {
                if (e.key === "Enter") {
                  e.preventDefault();
                  void doSearch(query);
                }
              }}
              contentBefore={<SearchRegular />}
              placeholder="Search by code (0x80070005) or description (access denied)"
            />

            <div aria-live="polite" style={{ minHeight: "18px" }}>
              {isSearching && (
                <span
                  style={{
                    fontSize: "11px",
                    color: tokens.colorNeutralForeground3,
                  }}
                >
                  Searching...
                </span>
              )}
              {!isSearching && searchError && (
                <span
                  style={{
                    fontSize: "11px",
                    color: tokens.colorPaletteRedForeground1,
                  }}
                >
                  {searchError}
                </span>
              )}
              {!isSearching &&
                !searchError &&
                query.trim() &&
                results.length === 0 && (
                  <span
                    style={{
                      fontSize: "11px",
                      color: tokens.colorNeutralForeground3,
                    }}
                  >
                    No results found
                  </span>
                )}
            </div>

            {results.length > 0 && (
              <div
                style={{
                  maxHeight: "320px",
                  overflowY: "auto",
                }}
              >
                {results.map((r) => (
                  <div
                    key={r.codeHex}
                    style={{
                      display: "flex",
                      alignItems: "center",
                      gap: "8px",
                      padding: "6px 0",
                      borderBottom: `1px solid ${tokens.colorNeutralStroke2}`,
                    }}
                  >
                    <Badge
                      appearance="filled"
                      color={getCategoryColor(r.category)}
                      style={{ flexShrink: 0 }}
                    >
                      {r.category || "Unknown"}
                    </Badge>
                    <span
                      style={{
                        fontFamily: LOG_MONOSPACE_FONT_FAMILY,
                        fontSize: "12px",
                        flexShrink: 0,
                      }}
                    >
                      {r.codeHex}
                    </span>
                    <span
                      style={{
                        fontSize: "12px",
                        flex: 1,
                        overflow: "hidden",
                        textOverflow: "ellipsis",
                        whiteSpace: "nowrap",
                        color: r.found
                          ? tokens.colorNeutralForeground1
                          : tokens.colorNeutralForeground3,
                      }}
                    >
                      {r.description}
                    </span>
                    <Tooltip content="Copy to clipboard" relationship="label">
                      <Button
                        size="small"
                        appearance="subtle"
                        icon={<CopyRegular />}
                        onClick={() => void handleCopy(r)}
                      />
                    </Tooltip>
                  </div>
                ))}
              </div>
            )}

            {history.length > 0 && (
              <>
                <div
                  style={{
                    fontSize: "11px",
                    color: tokens.colorNeutralForeground3,
                    marginTop: "12px",
                    marginBottom: "4px",
                  }}
                >
                  Recent lookups
                </div>
                {history.map((h) => (
                  <div
                    key={h.codeHex}
                    style={{
                      display: "flex",
                      alignItems: "center",
                      gap: "8px",
                      padding: "6px 0",
                      borderBottom: `1px solid ${tokens.colorNeutralStroke2}`,
                      cursor: "pointer",
                    }}
                    onClick={() => handleHistoryClick(h)}
                    onKeyDown={(e) => {
                      if (e.key === " ") {
                        e.preventDefault();
                      } else if (e.key === "Enter") {
                        handleHistoryClick(h);
                      }
                    }}
                    onKeyUp={(e) => {
                      if (e.key === " ") {
                        handleHistoryClick(h);
                      }
                    }}
                    role="button"
                    tabIndex={0}
                  >
                    <Badge
                      appearance="filled"
                      color={getCategoryColor(h.category)}
                      style={{ flexShrink: 0 }}
                    >
                      {h.category || "Unknown"}
                    </Badge>
                    <span
                      style={{
                        fontFamily: LOG_MONOSPACE_FONT_FAMILY,
                        fontSize: "12px",
                        flexShrink: 0,
                      }}
                    >
                      {h.codeHex}
                    </span>
                    <span
                      style={{
                        fontSize: "12px",
                        flex: 1,
                        overflow: "hidden",
                        textOverflow: "ellipsis",
                        whiteSpace: "nowrap",
                        color: h.found
                          ? tokens.colorNeutralForeground1
                          : tokens.colorNeutralForeground3,
                      }}
                    >
                      {h.description}
                    </span>
                    <Tooltip content="Copy to clipboard" relationship="label">
                      <Button
                        size="small"
                        appearance="subtle"
                        icon={<CopyRegular />}
                        onClick={(e) => {
                          e.stopPropagation();
                          void handleCopy(h);
                        }}
                      />
                    </Tooltip>
                  </div>
                ))}
              </>
            )}
          </DialogContent>
          <DialogActions>
            <Button appearance="secondary" onClick={onClose}>
              Close
            </Button>
          </DialogActions>
        </DialogBody>
      </DialogSurface>
    </Dialog>
  );
}
