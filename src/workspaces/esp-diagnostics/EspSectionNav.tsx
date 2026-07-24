import { tokens } from "@fluentui/react-components";
import { ArrowUpRegular } from "@fluentui/react-icons";
import { LOG_MONOSPACE_FONT_FAMILY } from "../../lib/log-accessibility";

export interface EspNavSection {
  id: string;
  label: string;
}

interface EspSectionNavProps {
  sections: EspNavSection[];
}

function jumpTo(id: string) {
  document
    .getElementById(id)
    ?.scrollIntoView({ behavior: "smooth", block: "start" });
}

const pill = {
  height: 22,
  padding: "0 9px",
  cursor: "pointer",
  border: `1px solid ${tokens.colorNeutralStroke1}`,
  borderRadius: 11,
  backgroundColor: tokens.colorNeutralBackground1,
  color: tokens.colorNeutralForeground2,
  fontFamily: LOG_MONOSPACE_FONT_FAMILY,
  fontSize: 10,
  fontWeight: 700,
} as const;

export function EspSectionNav({ sections }: EspSectionNavProps) {
  return (
    <nav
      aria-label="Jump to section"
      style={{
        position: "sticky",
        top: 0,
        zIndex: 3,
        display: "flex",
        flexWrap: "wrap",
        alignItems: "center",
        gap: 5,
        padding: "5px 10px",
        borderBottom: `1px solid ${tokens.colorNeutralStroke2}`,
        backgroundColor: tokens.colorNeutralBackground2,
      }}
    >
      <button
        type="button"
        onClick={() => jumpTo("esp-diagnostics-heading")}
        style={{
          ...pill,
          display: "inline-flex",
          alignItems: "center",
          gap: 3,
          color: tokens.colorBrandForeground1,
        }}
      >
        <ArrowUpRegular aria-hidden="true" /> Top
      </button>
      <span
        aria-hidden="true"
        style={{
          color: tokens.colorNeutralForeground4,
          fontFamily: LOG_MONOSPACE_FONT_FAMILY,
          fontSize: 10,
          letterSpacing: "0.06em",
          textTransform: "uppercase",
        }}
      >
        Jump to
      </span>
      {sections.map((section) => (
        <button
          key={section.id}
          type="button"
          onClick={() => jumpTo(section.id)}
          style={pill}
        >
          {section.label}
        </button>
      ))}
    </nav>
  );
}
