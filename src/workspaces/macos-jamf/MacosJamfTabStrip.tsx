import { TabList, Tab } from "@fluentui/react-components";
import type { MacosJamfTabId } from "./types";

interface Props {
  active: MacosJamfTabId;
  onChange: (id: MacosJamfTabId) => void;
}

const TABS: { id: MacosJamfTabId; label: string }[] = [
  { id: "overview", label: "Overview" },
  { id: "policies", label: "Policies" },
  { id: "profiles", label: "Profiles" },
  { id: "self-service", label: "Self Service" },
  { id: "connect", label: "JAMF Connect" },
  { id: "logs", label: "Logs" },
];

export function MacosJamfTabStrip({ active, onChange }: Props) {
  return (
    <TabList
      selectedValue={active}
      onTabSelect={(_, data) => onChange(data.value as MacosJamfTabId)}
    >
      {TABS.map((t) => (
        <Tab key={t.id} value={t.id}>
          {t.label}
        </Tab>
      ))}
    </TabList>
  );
}
