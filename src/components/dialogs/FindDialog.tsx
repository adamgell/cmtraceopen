import { useEffect, useRef } from "react";
import { useLogStore } from "../../stores/log-store";

interface FindDialogProps {
  isOpen: boolean;
  onClose: () => void;
}

export function FindDialog({ isOpen, onClose }: FindDialogProps) {
  const inputRef = useRef<HTMLInputElement>(null);

  const searchText = useLogStore((s) => s.findQuery);
  const caseSensitive = useLogStore((s) => s.findCaseSensitive);
  const statusText = useLogStore((s) => s.findStatusText);
  const setFindQuery = useLogStore((s) => s.setFindQuery);
  const setFindCaseSensitive = useLogStore((s) => s.setFindCaseSensitive);
  const findNext = useLogStore((s) => s.findNext);
  const findPrevious = useLogStore((s) => s.findPrevious);

  useEffect(() => {
    if (isOpen && inputRef.current) {
      inputRef.current.focus();
      inputRef.current.select();
    }
  }, [isOpen]);

  useEffect(() => {
    if (!isOpen) {
      return;
    }

    const handleKey = (event: KeyboardEvent) => {
      if (event.key === "Escape") {
        onClose();
        return;
      }

      if (event.key === "Enter" || event.key === "F3") {
        event.preventDefault();

        if (event.shiftKey) {
          findPrevious("find-dialog.keyboard");
          return;
        }

        findNext("find-dialog.keyboard");
      }
    };

    window.addEventListener("keydown", handleKey);
    return () => window.removeEventListener("keydown", handleKey);
  }, [findNext, findPrevious, isOpen, onClose]);

  if (!isOpen) {
    return null;
  }

  return (
    <div
      style={{
        position: "fixed",
        top: 0,
        left: 0,
        right: 0,
        bottom: 0,
        backgroundColor: "rgba(0,0,0,0.3)",
        display: "flex",
        alignItems: "flex-start",
        justifyContent: "center",
        paddingTop: "80px",
        zIndex: 1000,
      }}
      onClick={(event) => {
        if (event.target === event.currentTarget) {
          onClose();
        }
      }}
    >
      <div
        style={{
          backgroundColor: "#f0f0f0",
          border: "1px solid #999",
          borderRadius: "4px",
          padding: "12px",
          minWidth: "400px",
          boxShadow: "0 4px 12px rgba(0,0,0,0.3)",
        }}
      >
        <div
          style={{
            fontSize: "13px",
            fontWeight: "bold",
            marginBottom: "8px",
          }}
        >
          Find
        </div>

        <div style={{ display: "flex", gap: "6px", marginBottom: "8px" }}>
          <label style={{ fontSize: "12px", lineHeight: "24px" }}>
            Find what:
          </label>
          <input
            ref={inputRef}
            type="text"
            value={searchText}
            onChange={(event) => setFindQuery(event.target.value)}
            style={{
              flex: 1,
              fontSize: "12px",
              padding: "2px 4px",
            }}
          />
        </div>

        <div style={{ display: "flex", gap: "8px", alignItems: "center", marginBottom: "8px" }}>
          <label style={{ fontSize: "12px", display: "flex", alignItems: "center", gap: "4px" }}>
            <input
              type="checkbox"
              checked={caseSensitive}
              onChange={(event) => setFindCaseSensitive(event.target.checked)}
            />
            Match case
          </label>
          {statusText && (
            <span style={{ fontSize: "11px", color: "#666" }}>{statusText}</span>
          )}
        </div>

        <div style={{ display: "flex", gap: "6px", justifyContent: "flex-end" }}>
          <button onClick={() => findPrevious("find-dialog.button.previous")}>Find Previous</button>
          <button onClick={() => findNext("find-dialog.button.next")}>Find Next</button>
          <button onClick={onClose}>Close</button>
        </div>
      </div>
    </div>
  );
}
