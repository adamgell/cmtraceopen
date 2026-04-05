use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EvtxRecord {
    pub id: u64,
    pub event_record_id: u64,
    pub timestamp: String,
    pub timestamp_epoch: i64,
    pub provider: String,
    pub channel: String,
    pub event_id: u32,
    pub level: EvtxLevel,
    pub computer: String,
    pub message: String,
    pub event_data: Vec<EvtxField>,
    pub raw_xml: String,
    pub source_label: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EvtxField {
    pub name: String,
    pub value: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EvtxLevel {
    Critical,
    Error,
    Warning,
    Information,
    Verbose,
}

impl EvtxLevel {
    pub fn from_level_value(level: u8) -> Self {
        match level {
            1 => Self::Critical,
            2 => Self::Error,
            3 => Self::Warning,
            5 => Self::Verbose,
            _ => Self::Information,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EvtxChannelInfo {
    pub name: String,
    pub event_count: u64,
    pub source_type: ChannelSourceType,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ChannelSourceType {
    Live,
    File { path: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EvtxParseResult {
    pub records: Vec<EvtxRecord>,
    pub channels: Vec<EvtxChannelInfo>,
    pub total_records: u64,
    pub parse_errors: u32,
    pub error_messages: Vec<String>,
}
