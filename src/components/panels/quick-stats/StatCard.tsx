import { memo } from "react";
import { Card, Text, tokens } from "@fluentui/react-components";

export interface StatCardProps {
  label: string;
  value: number;
  color?: "neutral" | "error" | "warning" | "success" | "info";
  subtitle?: string;
  active?: boolean;
  onClick?: () => void;
}

export const StatCard = memo(function StatCard({
  label,
  value,
  color = "neutral",
  subtitle,
  active,
  onClick,
}: StatCardProps) {
  const colorStyles = {
    neutral: {
      borderColor: tokens.colorNeutralStroke1,
      backgroundColor: tokens.colorNeutralBackground1,
      valueColor: tokens.colorNeutralForeground1,
    },
    error: {
      borderColor: tokens.colorStatusDangerBorder1,
      backgroundColor: tokens.colorStatusDangerBackground2,
      valueColor: tokens.colorStatusDangerForeground1,
    },
    warning: {
      borderColor: tokens.colorStatusWarningBorder1,
      backgroundColor: tokens.colorStatusWarningBackground2,
      valueColor: tokens.colorStatusWarningForeground1,
    },
    success: {
      borderColor: tokens.colorStatusSuccessBorder1,
      backgroundColor: tokens.colorStatusSuccessBackground2,
      valueColor: tokens.colorStatusSuccessForeground1,
    },
    info: {
      borderColor: tokens.colorBrandForeground1,
      backgroundColor: tokens.colorBrandBackground2,
      valueColor: tokens.colorBrandForeground1,
    },
  };

  const styles = colorStyles[color];

  return (
    <Card
      appearance="filled-alternative"
      role={onClick ? "button" : undefined}
      onClick={onClick}
      style={{
        backgroundColor: styles.backgroundColor,
        border: active
          ? `2px solid ${styles.valueColor}`
          : `1px solid ${styles.borderColor}`,
        borderRadius: "4px",
        padding: "4px 8px",
        minWidth: "52px",
        cursor: onClick ? "pointer" : undefined,
        outline: active ? `1px solid ${styles.valueColor}` : undefined,
        outlineOffset: "1px",
      }}
    >
      <div style={{ display: "flex", alignItems: "baseline", gap: "4px" }}>
        <Text
          size={300}
          style={{
            color: styles.valueColor,
            fontWeight: 600,
          }}
        >
          {value.toLocaleString()}
        </Text>
        <Text
          size={100}
          style={{
            color: tokens.colorNeutralForeground3,
            textTransform: "uppercase",
            letterSpacing: "0.3px",
            fontSize: "10px",
          }}
        >
          {label}
        </Text>
      </div>
      {subtitle && (
        <Text
          style={{
            color: tokens.colorNeutralForeground3,
            display: "block",
            fontSize: "9px",
            lineHeight: "12px",
          }}
        >
          {subtitle}
        </Text>
      )}
    </Card>
  );
});
