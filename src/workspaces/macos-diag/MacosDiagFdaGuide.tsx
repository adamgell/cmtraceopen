import {
  Button,
  makeStyles,
  shorthands,
  tokens,
} from "@fluentui/react-components";

const useStyles = makeStyles({
  root: {
    display: "flex",
    flexDirection: "column",
    alignItems: "center",
    justifyContent: "center",
    flex: 1,
    ...shorthands.padding("40px"),
    backgroundImage:
      `linear-gradient(180deg, ${tokens.colorNeutralBackground1} 0%, ${tokens.colorNeutralBackground2} 100%)`,
    textAlign: "center" as const,
  },
  icon: {
    width: "72px",
    height: "72px",
    backgroundColor: tokens.colorPaletteYellowBackground1,
    ...shorthands.border("2px", "solid", tokens.colorPaletteYellowBorder2),
    ...shorthands.borderRadius("20px"),
    display: "flex",
    alignItems: "center",
    justifyContent: "center",
    fontSize: "32px",
    marginBottom: "20px",
  },
  title: {
    fontSize: "20px",
    fontWeight: 700,
    color: tokens.colorNeutralForeground1,
    marginBottom: "8px",
    letterSpacing: "-0.3px",
  },
  desc: {
    fontSize: "13.5px",
    color: tokens.colorNeutralForeground3,
    maxWidth: "420px",
    marginBottom: "28px",
    lineHeight: "1.6",
  },
  steps: {
    textAlign: "left" as const,
    maxWidth: "400px",
    marginBottom: "28px",
  },
  step: {
    display: "flex",
    gap: "12px",
    alignItems: "flex-start",
    marginBottom: "14px",
  },
  stepNum: {
    width: "24px",
    height: "24px",
    backgroundColor: tokens.colorBrandBackground,
    color: tokens.colorNeutralForegroundOnBrand,
    ...shorthands.borderRadius("50%"),
    display: "flex",
    alignItems: "center",
    justifyContent: "center",
    fontSize: "12px",
    fontWeight: 700,
    flexShrink: 0,
  },
  stepText: {
    fontSize: "13px",
    color: tokens.colorNeutralForeground1,
    paddingTop: "2px",
    lineHeight: "1.5",
  },
  code: {
    fontFamily: tokens.fontFamilyMonospace,
    fontSize: "11.5px",
    backgroundColor: tokens.colorNeutralBackground3,
    ...shorthands.padding("1px", "5px"),
    ...shorthands.borderRadius("3px"),
    color: tokens.colorBrandForeground1,
  },
  actions: {
    display: "flex",
    gap: "10px",
  },
});

interface Props {
  onRecheck: () => void;
}

export function MacosDiagFdaGuide({ onRecheck }: Props) {
  const styles = useStyles();

  const handleOpenSettings = async () => {
    try {
      // Use Tauri invoke to open System Settings via the backend
      const { invoke } = await import("@tauri-apps/api/core");
      await invoke("macos_open_system_settings");
    } catch {
      // Silently fail if the command is not available
    }
  };

  return (
    <div className={styles.root}>
      <div className={styles.icon}>&#x1F512;</div>
      <div className={styles.title}>Full Disk Access Required</div>
      <div className={styles.desc}>
        CMTrace Open needs Full Disk Access to read system logs and diagnostic
        data from protected directories.
      </div>

      <div className={styles.steps}>
        <div className={styles.step}>
          <div className={styles.stepNum}>1</div>
          <div className={styles.stepText}>
            Open <strong>System Settings</strong>
          </div>
        </div>
        <div className={styles.step}>
          <div className={styles.stepNum}>2</div>
          <div className={styles.stepText}>
            Navigate to <strong>Privacy & Security</strong> &rarr;{" "}
            <strong>Full Disk Access</strong>
          </div>
        </div>
        <div className={styles.step}>
          <div className={styles.stepNum}>3</div>
          <div className={styles.stepText}>
            Click <span className={styles.code}>+</span> and select{" "}
            <strong>CMTrace Open</strong>
          </div>
        </div>
        <div className={styles.step}>
          <div className={styles.stepNum}>4</div>
          <div className={styles.stepText}>
            Toggle the switch to <strong>ON</strong>
          </div>
        </div>
        <div className={styles.step}>
          <div className={styles.stepNum}>5</div>
          <div className={styles.stepText}>
            Restart <strong>CMTrace Open</strong>
          </div>
        </div>
      </div>

      <div className={styles.actions}>
        <Button appearance="primary" size="large" onClick={onRecheck}>
          Re-check FDA Status
        </Button>
        <Button appearance="secondary" size="large" onClick={handleOpenSettings}>
          Open System Settings
        </Button>
      </div>
    </div>
  );
}
