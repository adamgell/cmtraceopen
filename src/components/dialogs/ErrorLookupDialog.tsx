import { useEffect, useRef, useState } from "react";
import { invoke } from "@tauri-apps/api/core";

interface ErrorLookupResult {
  codeHex: string;
  codeDecimal: string;
  description: string;
  found: boolean;
}

interface ErrorLookupDialogProps {
  isOpen: boolean;
  onClose: () => void;
}

function formatLookupError(err: unknown): string {
  if (typeof err === "string") return err;
  if (err && typeof err === "object" && "message" in err) {
    return String((err as { message: unknown }).message);
  }
  return "Lookup failed. Please try again.";
}

export function ErrorLookupDialog({ isOpen, onClose }: ErrorLookupDialogProps) {
  const [input, setInput] = useState("");
  const [result, setResult] = useState<ErrorLookupResult | null>(null);
  const [isLookingUp, setIsLookingUp] = useState(false);
  const [lookupError, setLookupError] = useState<string | null>(null);
  const inputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    if (isOpen && inputRef.current) {
      inputRef.current.focus();
      inputRef.current.select();
    }

    if (!isOpen) {
      setIsLookingUp(false);
      setLookupError(null);
      setResult(null);
      setInput("");
    }
  }, [isOpen]);

  useEffect(() => {
    if (!isOpen) return;
    const handleKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") onClose();
    };
    window.addEventListener("keydown", handleKey);
    return () => window.removeEventListener("keydown", handleKey);
  }, [isOpen, onClose]);

  const handleLookup = async () => {
    const code = input.trim();
    if (!code || isLookingUp) {
      if (!code) {
        setLookupError("Enter an error code to look up.");
        setResult(null);
      }
      return;
    }

    setIsLookingUp(true);
    setLookupError(null);
    setResult(null);

    try {
      const res = await invoke<ErrorLookupResult>("lookup_error_code", { code });
      setResult(res);
    } catch (err) {
      console.error("Lookup failed", { code, error: err });
      setLookupError(formatLookupError(err));
    } finally {
      setIsLookingUp(false);
    }
  };

  if (!isOpen) return null;

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
      onClick={(e) => {
        if (e.target === e.currentTarget) onClose();
      }}
    >
      <div
        style={{
          backgroundColor: "#f0f0f0",
          border: "1px solid #999",
          borderRadius: "4px",
          padding: "12px",
          minWidth: "450px",
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
          Error Lookup
        </div>

        <div style={{ display: "flex", gap: "6px", marginBottom: "8px" }}>
          <label htmlFor="error-code-input" style={{ fontSize: "12px", lineHeight: "24px" }}>
            Error code:
          </label>
          <input
            id="error-code-input"
            ref={inputRef}
            type="text"
            value={input}
            onChange={(e) => {
              setInput(e.target.value);
              setLookupError(null);
            }}
            onKeyDown={(e) => {
              if (e.key === "Enter") {
                e.preventDefault();
                void handleLookup();
              }
            }}
            placeholder="0x80070005 or -2147024891"
            style={{
              flex: 1,
              fontSize: "12px",
              padding: "2px 4px",
              fontFamily: "'Courier New', monospace",
            }}
            disabled={isLookingUp}
          />
          <button onClick={() => void handleLookup()} disabled={isLookingUp}>
            {isLookingUp ? "Looking up..." : "Lookup"}
          </button>
        </div>

        <div aria-live="polite" style={{ minHeight: "18px", marginBottom: "8px" }}>
          {isLookingUp && <span style={{ fontSize: "11px", color: "#555" }}>Searching known error codes...</span>}
          {!isLookingUp && lookupError && (
            <span style={{ fontSize: "11px", color: "#a40000" }}>{lookupError}</span>
          )}
        </div>

        {result && (
          <div
            style={{
              backgroundColor: "#fff",
              border: "1px solid #ccc",
              borderRadius: "2px",
              padding: "8px",
              fontSize: "12px",
            }}
          >
            <div style={{ marginBottom: "4px" }}>
              <strong>Hex:</strong>{" "}
              <span style={{ fontFamily: "'Courier New', monospace" }}>
                {result.codeHex}
              </span>
            </div>
            <div style={{ marginBottom: "4px" }}>
              <strong>Decimal:</strong>{" "}
              <span style={{ fontFamily: "'Courier New', monospace" }}>
                {result.codeDecimal}
              </span>
            </div>
            <div
              style={{
                marginTop: "6px",
                color: result.found ? "#000" : "#666",
              }}
            >
              <strong>{result.found ? "Description:" : "Not found:"}</strong>{" "}
              {result.description}
            </div>
          </div>
        )}

        <div
          style={{
            display: "flex",
            justifyContent: "flex-end",
            marginTop: "10px",
          }}
        >
          <button onClick={onClose}>Close</button>
        </div>
      </div>
    </div>
  );
}
