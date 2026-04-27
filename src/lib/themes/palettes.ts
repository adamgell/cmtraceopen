import type { LogSeverityPalette } from "../constants";
import type { ThemeId } from "./types";

export const themeSeverityPalettes: Record<ThemeId, LogSeverityPalette> = {
  light: {
    error: { background: "#FEE2E2", text: "#7F1D1D" },
    warning: { background: "#FEF3C7", text: "#78350F" },
    info: { background: "#FFFFFF", text: "#111827" },
    highlightDefault: "#FDE68A",
    mergeColors: [
      "#2563eb", "#dc2626", "#16a34a", "#9333ea",
      "#ea580c", "#0891b2", "#c026d3", "#854d0e",
    ],
    whatifOverlay: "rgba(147, 51, 234, 0.20)",
    whatifText: "#9333ea",
    status: {
      success: { foreground: "#0e700e", background: "rgba(14, 112, 14, 0.1)" },
      warning: { foreground: "#bc4b09", background: "rgba(188, 75, 9, 0.1)" },
      error: { foreground: "#b10e1c", background: "rgba(177, 14, 28, 0.1)" },
    },
  },
  dark: {
    error: { background: "#7F1D1D", text: "#FCA5A5" },
    warning: { background: "#78350F", text: "#FDE68A" },
    info: { background: "#1E1E1E", text: "#D4D4D4" },
    highlightDefault: "#854D0E",
    mergeColors: [
      "#60a5fa", "#f87171", "#4ade80", "#c084fc",
      "#fb923c", "#22d3ee", "#e879f9", "#d97706",
    ],
    whatifOverlay: "rgba(192, 132, 252, 0.25)",
    whatifText: "#c084fc",
    status: {
      success: { foreground: "#4ade80", background: "rgba(74, 222, 128, 0.15)" },
      warning: { foreground: "#fbbf24", background: "rgba(251, 191, 36, 0.15)" },
      error: { foreground: "#f87171", background: "rgba(248, 113, 113, 0.15)" },
    },
  },
  "high-contrast": {
    error: { background: "#000000", text: "#FF0000" },
    warning: { background: "#000000", text: "#FFFF00" },
    info: { background: "#000000", text: "#FFFFFF" },
    highlightDefault: "#00FF00",
    mergeColors: [
      "#00BFFF", "#FF4500", "#00FF00", "#FF00FF",
      "#FFA500", "#00FFFF", "#FF69B4", "#FFD700",
    ],
    whatifOverlay: "rgba(255, 0, 255, 0.30)",
    whatifText: "#FF00FF",
    status: {
      success: { foreground: "#00FF00", background: "rgba(0, 255, 0, 0.15)" },
      warning: { foreground: "#FFFF00", background: "rgba(255, 255, 0, 0.15)" },
      error: { foreground: "#FF0000", background: "rgba(255, 0, 0, 0.15)" },
    },
  },
  "classic-cmtrace": {
    error: { background: "#FF0000", text: "#FFFF00" },
    warning: { background: "#FFFF00", text: "#000000" },
    info: { background: "#FFFFFF", text: "#000000" },
    highlightDefault: "#FFFF00",
    mergeColors: [
      "#2563eb", "#dc2626", "#16a34a", "#9333ea",
      "#ea580c", "#0891b2", "#c026d3", "#854d0e",
    ],
    whatifOverlay: "rgba(147, 51, 234, 0.20)",
    whatifText: "#9333ea",
    status: {
      success: { foreground: "#0e700e", background: "rgba(14, 112, 14, 0.1)" },
      warning: { foreground: "#bc4b09", background: "rgba(188, 75, 9, 0.1)" },
      error: { foreground: "#b10e1c", background: "rgba(177, 14, 28, 0.1)" },
    },
  },
  "solarized-dark": {
    error: { background: "#073642", text: "#DC322F" },
    warning: { background: "#073642", text: "#B58900" },
    info: { background: "#002B36", text: "#839496" },
    highlightDefault: "#586E75",
    mergeColors: [
      "#268BD2", "#DC322F", "#859900", "#6C71C4",
      "#CB4B16", "#2AA198", "#D33682", "#B58900",
    ],
    whatifOverlay: "rgba(108, 113, 196, 0.25)",
    whatifText: "#6C71C4",
    status: {
      success: { foreground: "#859900", background: "rgba(133, 153, 0, 0.15)" },
      warning: { foreground: "#B58900", background: "rgba(181, 137, 0, 0.15)" },
      error: { foreground: "#DC322F", background: "rgba(220, 50, 47, 0.15)" },
    },
  },
  nord: {
    error: { background: "#3B4252", text: "#BF616A" },
    warning: { background: "#3B4252", text: "#EBCB8B" },
    info: { background: "#2E3440", text: "#D8DEE9" },
    highlightDefault: "#4C566A",
    mergeColors: [
      "#88C0D0", "#BF616A", "#A3BE8C", "#B48EAD",
      "#D08770", "#8FBCBB", "#5E81AC", "#EBCB8B",
    ],
    whatifOverlay: "rgba(180, 142, 173, 0.25)",
    whatifText: "#B48EAD",
    status: {
      success: { foreground: "#A3BE8C", background: "rgba(163, 190, 140, 0.15)" },
      warning: { foreground: "#EBCB8B", background: "rgba(235, 203, 139, 0.15)" },
      error: { foreground: "#BF616A", background: "rgba(191, 97, 106, 0.15)" },
    },
  },
  dracula: {
    error: { background: "#44475A", text: "#FF5555" },
    warning: { background: "#44475A", text: "#F1FA8C" },
    info: { background: "#282A36", text: "#F8F8F2" },
    highlightDefault: "#6272A4",
    mergeColors: [
      "#8BE9FD", "#FF5555", "#50FA7B", "#BD93F9",
      "#FFB86C", "#FF79C6", "#6272A4", "#F1FA8C",
    ],
    whatifOverlay: "rgba(189, 147, 249, 0.25)",
    whatifText: "#BD93F9",
    status: {
      success: { foreground: "#50FA7B", background: "rgba(80, 250, 123, 0.15)" },
      warning: { foreground: "#F1FA8C", background: "rgba(241, 250, 140, 0.15)" },
      error: { foreground: "#FF5555", background: "rgba(255, 85, 85, 0.15)" },
    },
  },
  "hotdog-stand": {
    error: { background: "#FF0000", text: "#FFFF00" },
    warning: { background: "#FFFF00", text: "#FF0000" },
    info: { background: "#FF0000", text: "#FFFF00" },
    highlightDefault: "#00FF00",
    mergeColors: [
      "#00BFFF", "#00FF00", "#FF69B4", "#FFFF00",
      "#FFA500", "#00FFFF", "#FF00FF", "#FFFFFF",
    ],
    whatifOverlay: "rgba(255, 0, 255, 0.30)",
    whatifText: "#FF00FF",
    status: {
      success: { foreground: "#00FF00", background: "rgba(0, 255, 0, 0.15)" },
      warning: { foreground: "#FFFF00", background: "rgba(255, 255, 0, 0.15)" },
      error: { foreground: "#FF0000", background: "rgba(255, 0, 0, 0.15)" },
    },
  },
};
