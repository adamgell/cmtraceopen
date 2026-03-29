import type { ReactNode } from "react";
import { tokens } from "@fluentui/react-components";
import type { FactRow } from "./dsregcmd-formatters";

export function StatCard({
  title,
  value,
  caption,
  tone = "neutral",
}: {
  title: string;
  value: string;
  caption: string;
  tone?: "neutral" | "good" | "warn" | "bad";
}) {
  const tones = {
    neutral: { border: tokens.colorNeutralStroke2, background: tokens.colorNeutralCardBackground, value: tokens.colorNeutralForeground1 },
    good: { border: tokens.colorPaletteGreenBorder2, background: tokens.colorPaletteGreenBackground1, value: tokens.colorPaletteGreenForeground1 },
    warn: { border: tokens.colorPaletteYellowBorder2, background: tokens.colorPaletteYellowBackground1, value: tokens.colorPaletteMarigoldForeground2 },
    bad: { border: tokens.colorPaletteRedBorder2, background: tokens.colorPaletteRedBackground1, value: tokens.colorPaletteRedForeground1 },
  } as const;

  const colors = tones[tone];

  return (
    <div
      style={{
        border: `1px solid ${colors.border}`,
        backgroundColor: colors.background,
        padding: "12px",
        minWidth: 0,
        borderRadius: "10px",
      }}
    >
      <div
        style={{
          fontSize: "11px",
          color: tokens.colorNeutralForeground3,
          textTransform: "uppercase",
          letterSpacing: "0.04em",
        }}
      >
        {title}
      </div>
      <div
        style={{
          marginTop: "6px",
          fontSize: "20px",
          fontWeight: 700,
          color: colors.value,
          lineHeight: 1.2,
        }}
      >
        {value}
      </div>
      <div
        style={{
          marginTop: "6px",
          fontSize: "12px",
          color: tokens.colorNeutralForeground2,
          lineHeight: 1.45,
        }}
      >
        {caption}
      </div>
    </div>
  );
}

export function SectionFrame({
  title,
  caption,
  children,
}: {
  title: string;
  caption: string;
  children: ReactNode;
}) {
  return (
    <section
      style={{
        border: `1px solid ${tokens.colorNeutralStroke2}`,
        backgroundColor: tokens.colorNeutralCardBackground,
        borderRadius: "10px",
        overflow: "hidden",
        flexShrink: 0,
      }}
    >
      <div style={{ padding: "12px 14px", backgroundColor: tokens.colorNeutralBackground3 }}>
        <div style={{ fontSize: "14px", fontWeight: 700, color: tokens.colorNeutralForeground1 }}>
          {title}
        </div>
        <div style={{ marginTop: "4px", fontSize: "12px", color: tokens.colorNeutralForeground3 }}>
          {caption}
        </div>
      </div>
      <div style={{ borderTop: `1px solid ${tokens.colorNeutralStroke2}` }} />
      <div style={{ padding: "14px" }}>{children}</div>
    </section>
  );
}

export function EmptyWorkspace({ title, body }: { title: string; body: string }) {
  return (
    <div
      style={{
        margin: "18px",
        border: `1px dashed ${tokens.colorNeutralStroke2}`,
        backgroundColor: tokens.colorNeutralBackground3,
        padding: "24px",
        color: tokens.colorNeutralForeground2,
        borderRadius: "12px",
      }}
    >
      <div style={{ fontSize: "18px", fontWeight: 700, color: tokens.colorNeutralForeground1 }}>
        {title}
      </div>
      <div style={{ marginTop: "8px", fontSize: "13px", lineHeight: 1.6 }}>
        {body}
      </div>
    </div>
  );
}

export function FlowBox({
  title,
  detail,
  tone = "neutral",
}: {
  title: string;
  detail: string;
  tone?: FactRow["tone"];
}) {
  const colors = {
    neutral: { border: tokens.colorNeutralStroke2, background: tokens.colorNeutralCardBackground, text: tokens.colorNeutralForeground1 },
    good: { border: tokens.colorPaletteGreenBorder2, background: tokens.colorPaletteGreenBackground1, text: tokens.colorPaletteGreenForeground1 },
    warn: { border: tokens.colorPaletteYellowBorder2, background: tokens.colorPaletteYellowBackground1, text: tokens.colorPaletteMarigoldForeground2 },
    bad: { border: tokens.colorPaletteRedBorder2, background: tokens.colorPaletteRedBackground1, text: tokens.colorPaletteRedForeground1 },
  } as const;
  const palette = colors[tone ?? "neutral"];

  return (
    <div
      style={{
        flex: 1,
        minWidth: "180px",
        border: `1px solid ${palette.border}`,
        backgroundColor: palette.background,
        padding: "12px",
        borderRadius: "10px",
      }}
    >
      <div style={{ fontSize: "12px", fontWeight: 700, color: palette.text }}>
        {title}
      </div>
      <div
        style={{
          marginTop: "6px",
          fontSize: "12px",
          color: tokens.colorNeutralForeground2,
          lineHeight: 1.5,
        }}
      >
        {detail}
      </div>
    </div>
  );
}

export function TabButton({
  label,
  count,
  isActive,
  onClick,
}: {
  label: string;
  count?: number;
  isActive: boolean;
  onClick: () => void;
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      style={{
        padding: "8px 14px",
        fontSize: 13,
        fontWeight: isActive ? 600 : 400,
        color: isActive ? tokens.colorBrandForeground1 : tokens.colorNeutralForeground3,
        background: "transparent",
        border: "none",
        borderBottom: isActive ? `2px solid ${tokens.colorBrandForeground1}` : "2px solid transparent",
        cursor: "pointer",
        transition: "border-color 0.15s, color 0.15s",
        display: "flex",
        alignItems: "center",
        gap: 6,
      }}
    >
      {label}
      {count != null && count > 0 && (
        <span
          style={{
            fontSize: 11,
            padding: "1px 6px",
            borderRadius: 10,
            background: isActive ? tokens.colorPaletteBlueBackground2 : tokens.colorNeutralBackground3,
            color: isActive ? tokens.colorPaletteBlueForeground2 : tokens.colorNeutralForeground3,
          }}
        >
          {count}
        </span>
      )}
    </button>
  );
}
