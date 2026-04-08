import { memo } from "react";
import { Card, Text, tokens } from "@fluentui/react-components";

export interface StatCardProps {
  label: string;
  value: number;
  color?: "neutral" | "error" | "warning" | "info";
  subtitle?: string;
}

export const StatCard = memo(function StatCard({
  label,
  value,
  color = "neutral",
  subtitle,
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
      style={{
        backgroundColor: styles.backgroundColor,
        border: `1px solid ${styles.borderColor}`,
        borderRadius: "6px",
        padding: "12px 16px",
        minWidth: "100px",
        maxWidth: "140px",
      }}
    >
      <Text
        size={200}
        style={{
          color: tokens.colorNeutralForeground3,
          display: "block",
          marginBottom: "4px",
          textTransform: "uppercase",
          letterSpacing: "0.5px",
        }}
      >
        {label}
      </Text>
      <Text
        size={600}
        style={{
          color: styles.valueColor,
          fontWeight: 600,
          display: "block",
          marginBottom: subtitle ? "4px" : 0,
        }}
      >
        {value.toLocaleString()}
      </Text>
      {subtitle && (
        <Text
          size={200}
          style={{
            color: tokens.colorNeutralForeground3,
            display: "block",
          }}
        >
          {subtitle}
        </Text>
      )}
    </Card>
  );
});
