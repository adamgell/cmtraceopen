import {
  Button,
  makeStyles,
  shorthands,
  tokens,
} from "@fluentui/react-components";
import type { MacosDiagEnvironment } from "./types";

const useStyles = makeStyles({
  banner: {
    display: "flex",
    alignItems: "center",
    gap: "16px",
    ...shorthands.padding("14px", "20px"),
    backgroundImage:
      "none",
    backgroundColor: tokens.colorNeutralBackground2,
    borderBottom: `1px solid ${tokens.colorNeutralStroke1}`,
  },
  titleBlock: {
    display: "flex",
    flexDirection: "column",
    gap: "2px",
  },
  title: {
    fontSize: "16px",
    fontWeight: 700,
    color: tokens.colorNeutralForeground1,
    letterSpacing: "-0.2px",
  },
  subtitle: {
    fontSize: "12px",
    color: tokens.colorNeutralForeground3,
  },
  badges: {
    display: "flex",
    gap: "8px",
    flexWrap: "wrap" as const,
    marginLeft: "auto",
    alignItems: "center",
  },
  pillGranted: {
    display: "inline-flex",
    alignItems: "center",
    gap: "5px",
    ...shorthands.padding("4px", "10px"),
    ...shorthands.borderRadius("100px"),
    fontSize: "11px",
    fontWeight: 600,
    backgroundColor: tokens.colorPaletteGreenBackground1,
    color: tokens.colorPaletteGreenForeground1,
    ...shorthands.border("1px", "solid", tokens.colorPaletteGreenBorder2),
  },
  pillAvailable: {
    display: "inline-flex",
    alignItems: "center",
    gap: "5px",
    ...shorthands.padding("4px", "10px"),
    ...shorthands.borderRadius("100px"),
    fontSize: "11px",
    fontWeight: 600,
    backgroundColor: tokens.colorPaletteBlueBackground2,
    color: tokens.colorPaletteBlueForeground2,
    ...shorthands.border("1px", "solid", tokens.colorPaletteBlueBorderActive),
  },
  pillMissing: {
    display: "inline-flex",
    alignItems: "center",
    gap: "5px",
    ...shorthands.padding("4px", "10px"),
    ...shorthands.borderRadius("100px"),
    fontSize: "11px",
    fontWeight: 600,
    backgroundColor: tokens.colorNeutralBackground3,
    color: tokens.colorNeutralForeground3,
    ...shorthands.border("1px", "solid", tokens.colorNeutralStroke1),
  },
  dot: {
    width: "6px",
    height: "6px",
    ...shorthands.borderRadius("50%"),
    flexShrink: 0,
  },
  dotGranted: {
    backgroundColor: tokens.colorPaletteGreenForeground1,
  },
  dotAvailable: {
    backgroundColor: tokens.colorPaletteBlueForeground2,
  },
  dotMissing: {
    backgroundColor: tokens.colorNeutralForeground3,
  },
});

interface Props {
  environment: MacosDiagEnvironment;
  onRefresh: () => void;
}

export function MacosDiagEnvironmentBanner({ environment, onRefresh }: Props) {
  const styles = useStyles();

  const tools = environment.tools;
  const dirs = environment.directories;

  const dirTotal = Object.values(dirs).length;
  const dirFound = Object.values(dirs).filter(Boolean).length;
  const dirMissing = dirTotal - dirFound;

  const fdaLabel =
    environment.fullDiskAccess === "granted"
      ? "Full Disk Access"
      : environment.fullDiskAccess === "unknown"
        ? "FDA Unknown"
        : "FDA Not Granted";

  const fdaPill =
    environment.fullDiskAccess === "granted"
      ? styles.pillGranted
      : styles.pillMissing;

  const fdaDot =
    environment.fullDiskAccess === "granted"
      ? styles.dotGranted
      : styles.dotMissing;

  return (
    <div className={styles.banner}>
      <div className={styles.titleBlock}>
        <div className={styles.title}>macOS Diagnostics</div>
        <div className={styles.subtitle}>
          macOS {environment.macosVersion} ({environment.macosBuild})
        </div>
      </div>

      <div className={styles.badges}>
        <span className={fdaPill}>
          <span className={`${styles.dot} ${fdaDot}`} />
          {fdaLabel}
        </span>

        {(
          [
            ["profiles", tools.profiles],
            ["mdatp", tools.mdatp],
            ["pkgutil", tools.pkgutil],
            ["log", tools.logCommand],
          ] as const
        ).map(([name, available]) => (
          <span
            key={name}
            className={available ? styles.pillAvailable : styles.pillMissing}
          >
            <span
              className={`${styles.dot} ${available ? styles.dotAvailable : styles.dotMissing}`}
            />
            {name}
          </span>
        ))}

        {dirMissing > 0 && (
          <span className={styles.pillMissing}>
            <span className={`${styles.dot} ${styles.dotMissing}`} />
            {dirMissing} dir{dirMissing > 1 ? "s" : ""} missing
          </span>
        )}

        <Button size="small" appearance="subtle" onClick={onRefresh}>
          Refresh All
        </Button>
      </div>
    </div>
  );
}
