import { useMemo, useState } from "react";
import { Button, Checkbox, Input, tokens } from "@fluentui/react-components";
import { useEvtxStore } from "../../stores/evtx-store";

export function ChannelPicker() {
  const channels = useEvtxStore((s) => s.channels);
  const selectedChannels = useEvtxStore((s) => s.selectedChannels);
  const toggleChannel = useEvtxStore((s) => s.toggleChannel);
  const selectAllChannels = useEvtxStore((s) => s.selectAllChannels);
  const deselectAllChannels = useEvtxStore((s) => s.deselectAllChannels);
  const [search, setSearch] = useState("");

  const filteredChannels = useMemo(() => {
    if (!search.trim()) return channels;
    const lower = search.toLowerCase();
    return channels.filter((c) => c.name.toLowerCase().includes(lower));
  }, [channels, search]);

  return (
    <div
      style={{
        display: "flex",
        flexDirection: "column",
        height: "100%",
        borderRight: `1px solid ${tokens.colorNeutralStroke2}`,
        width: "240px",
        minWidth: "200px",
        backgroundColor: tokens.colorNeutralBackground2,
      }}
    >
      <div
        style={{
          padding: "8px",
          borderBottom: `1px solid ${tokens.colorNeutralStroke2}`,
          display: "flex",
          flexDirection: "column",
          gap: "6px",
        }}
      >
        <div
          style={{
            fontSize: "11px",
            fontWeight: 600,
            color: tokens.colorNeutralForeground3,
            textTransform: "uppercase",
            letterSpacing: "0.5px",
          }}
        >
          Channels ({selectedChannels.size}/{channels.length})
        </div>
        <Input
          value={search}
          onChange={(_, data) => setSearch(data.value)}
          placeholder="Filter channels..."
          size="small"
          style={{ width: "100%" }}
        />
        <div style={{ display: "flex", gap: "4px" }}>
          <Button size="small" appearance="subtle" onClick={selectAllChannels}>
            Select All
          </Button>
          <Button size="small" appearance="subtle" onClick={deselectAllChannels}>
            Deselect All
          </Button>
        </div>
      </div>

      <div style={{ flex: 1, overflowY: "auto", padding: "4px 8px" }}>
        {filteredChannels.map((channel) => (
          <div
            key={channel.name}
            style={{
              display: "flex",
              alignItems: "center",
              gap: "4px",
              padding: "2px 0",
            }}
          >
            <Checkbox
              checked={selectedChannels.has(channel.name)}
              onChange={() => toggleChannel(channel.name)}
              label={
                <span
                  style={{
                    fontSize: "12px",
                    color: tokens.colorNeutralForeground1,
                    overflow: "hidden",
                    textOverflow: "ellipsis",
                    whiteSpace: "nowrap",
                  }}
                  title={`${channel.name} (${channel.eventCount} events)`}
                >
                  {channel.name}
                  <span
                    style={{
                      marginLeft: "4px",
                      fontSize: "10px",
                      color: tokens.colorNeutralForeground4,
                    }}
                  >
                    ({channel.eventCount})
                  </span>
                </span>
              }
            />
          </div>
        ))}
        {filteredChannels.length === 0 && (
          <div
            style={{
              fontSize: "12px",
              color: tokens.colorNeutralForeground4,
              padding: "8px 0",
              textAlign: "center",
            }}
          >
            No channels match filter
          </div>
        )}
      </div>
    </div>
  );
}
