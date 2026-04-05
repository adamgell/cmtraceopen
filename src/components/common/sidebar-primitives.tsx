/**
 * Shared primitive components used across all workspace sidebars
 * (FileSidebar, IntuneSidebar, DsregcmdSidebar, SysmonSidebar).
 *
 * These were previously duplicated inline in each sidebar file. Keep all
 * sidebar-specific business logic in each workspace's own sidebar component.
 */

import type { ReactNode } from "react";
import {
  Badge,
  Button,
  Caption1,
  Subtitle2,
  tokens,
} from "@fluentui/react-components";

// ---------------------------------------------------------------------------
// SourceSummaryCard
// ---------------------------------------------------------------------------

export function SourceSummaryCard({
  badge,
  title,
  subtitle,
  body,
}: {
  badge: string;
  title: string;
  subtitle: string;
  body: ReactNode;
}) {
  return (
    <div
      style={{
        padding: "12px",
        borderBottom: `1px solid ${tokens.colorNeutralStroke2}`,
        backgroundColor: tokens.colorNeutralBackground2,
      }}
    >
      <Badge
        appearance="outline"
        color="brand"
        style={{
          fontWeight: 700,
          textTransform: "uppercase",
          letterSpacing: "0.05em",
        }}
      >
        {badge}
      </Badge>
      <Subtitle2
        title={title}
        style={{
          display: "block",
          marginTop: "8px",
          color: tokens.colorNeutralForeground1,
          fontSize: "inherit",
          fontWeight: 600,
          overflow: "hidden",
          textOverflow: "ellipsis",
          whiteSpace: "nowrap",
        }}
      >
        {title}
      </Subtitle2>
      <Caption1
        title={subtitle}
        style={{
          display: "block",
          marginTop: "4px",
          color: tokens.colorNeutralForeground3,
          fontSize: "0.85em",
          overflow: "hidden",
          textOverflow: "ellipsis",
          whiteSpace: "nowrap",
        }}
      >
        {subtitle}
      </Caption1>
      <div style={{ marginTop: "10px" }}>{body}</div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// SourceStatusNotice
// ---------------------------------------------------------------------------

export function SourceStatusNotice({
  kind,
  message,
  detail,
}: {
  kind: string;
  message: string;
  detail?: string;
}) {
  const colors =
    kind === "missing" || kind === "error"
      ? { border: tokens.colorPaletteRedBorder2, background: tokens.colorPaletteRedBackground1, text: tokens.colorPaletteRedForeground2 }
      : kind === "empty" || kind === "awaiting-file-selection"
        ? { border: tokens.colorPaletteYellowBorder2, background: tokens.colorPaletteYellowBackground1, text: tokens.colorPaletteMarigoldForeground2 }
        : { border: tokens.colorPaletteBlueBorderActive, background: tokens.colorPaletteBlueBackground2, text: tokens.colorPaletteBlueForeground2 };

  return (
    <div
      role="status"
      style={{
        padding: "9px 12px",
        borderBottom: `1px solid ${colors.border}`,
        backgroundColor: colors.background,
        color: colors.text,
        fontSize: "inherit",
        lineHeight: 1.4,
      }}
    >
      <div style={{ fontWeight: 600 }}>{message}</div>
      {detail && <div style={{ marginTop: "2px", opacity: 0.9 }}>{detail}</div>}
    </div>
  );
}

// ---------------------------------------------------------------------------
// SectionHeader
// ---------------------------------------------------------------------------

export function SectionHeader({ title, caption }: { title: string; caption?: string }) {
  return (
    <div
      style={{
        padding: "10px 12px 8px",
        borderBottom: `1px solid ${tokens.colorNeutralStroke2}`,
        backgroundColor: tokens.colorNeutralBackground2,
      }}
    >
      <Caption1
        style={{
          fontWeight: 600,
          color: tokens.colorNeutralForeground3,
          textTransform: "uppercase",
          letterSpacing: "0.04em",
        }}
      >
        {title}
      </Caption1>
      {caption && (
        <Caption1
          style={{
            display: "block",
            marginTop: "2px",
            color: tokens.colorNeutralForeground3,
          }}
        >
          {caption}
        </Caption1>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// EmptyState
// ---------------------------------------------------------------------------

export function EmptyState({ title, body }: { title: string; body: string }) {
  return (
    <div
      style={{
        padding: "18px 14px",
        color: tokens.colorNeutralForeground3,
        fontSize: "inherit",
        lineHeight: 1.5,
      }}
    >
      <Subtitle2 style={{ color: tokens.colorNeutralForeground1, marginBottom: "4px" }}>{title}</Subtitle2>
      <div>{body}</div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// SidebarActionButton
// ---------------------------------------------------------------------------

export function SidebarActionButton({
  label,
  disabled,
  onClick,
}: {
  label: string;
  disabled: boolean;
  onClick: () => void;
}) {
  return (
    <Button
      disabled={disabled}
      onClick={onClick}
      size="small"
      appearance="secondary"
      style={{
        justifyContent: "flex-start",
        minWidth: 0,
        flex: 1,
      }}
    >
      {label}
    </Button>
  );
}
