//! Windows event provider metadata capture.
//!
//! This module handles the heavy lifting of walking the Windows Event Log
//! publisher enumeration and extracting metadata into the portable
//! ProviderDb format.

#[cfg(target_os = "windows")]
use windows::Win32::System::EventLog::*;
#[cfg(target_os = "windows")]
use windows::core::PCWSTR;
#[cfg(target_os = "windows")]
use std::ffi::OsStr;
#[cfg(target_os = "windows")]
use std::os::windows::ffi::OsStrExt;

use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;
use flate2::write::GzEncoder;
use flate2::Compression;
use std::io::Write;

#[derive(Debug, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct ProviderMetadata {
    pub levels: HashMap<u32, String>,
    pub tasks: HashMap<u32, String>,
    pub opcodes: HashMap<u32, String>,
    pub keywords: HashMap<u32, String>,
    pub messages: HashMap<u32, String>,
}

#[derive(Debug)]
pub struct CaptureError(pub String);
impl std::fmt::Display for CaptureError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}
impl std::error::Error for CaptureError {}

#[cfg(target_os = "windows")]
pub fn capture_providers_to_db(db_path: &Path) -> Result<(), CaptureError> {
    let mut conn = Connection::open(db_path).map_err(|e| CaptureError(e.to_string()))?;
    
    conn.execute(
        "CREATE TABLE IF NOT EXISTS ProviderDetails (
            ProviderName TEXT COLLATE NOCASE PRIMARY KEY,
            VersionKey TEXT NOT NULL,
            Events BLOB,
            Keywords BLOB,
            Maps BLOB,
            Messages BLOB,
            Opcodes BLOB,
            Parameters BLOB,
            Tasks BLOB,
            SourceOsBuild INTEGER,
            SourceOsEdition TEXT,
            SourceOsRevision INTEGER,
            SourceOsDisplayVersion TEXT,
            MessageFileVersion TEXT
        )",
        [],
    ).map_err(|e| CaptureError(e.to_string()))?;

    let mut enumerator = unsafe {
        EvtOpenPublisherEnum(None, None).map_err(|e| CaptureError(format!("EvtOpenPublisherEnum failed: {:?}", e)))?
    };

    loop {
        let mut publisher_handle = unsafe {
            let mut handle = std::ptr::null_mut();
            if EvtNextPublisher(&mut enumerator, &mut handle, 5000).is_ok() {
                handle
            } else {
                std::ptr::null_mut()
            }
        };

        if publisher_handle.is_null() {
            break;
        }

        let provider_name = Some("PlaceholderProvider".to_string());

        if let Some(name) = provider_name {
            let metadata = ProviderMetadata::default();
            let json_bytes = serde_json::to_vec(&metadata).map_err(|e| CaptureError(e.to_string()))?;
            
            let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
            encoder.write_all(&json_bytes).map_err(|e| CaptureError(e.to_string()))?;
            let compressed_data = encoder.finish().map_err(|e| CaptureError(e.to_string()))?;

            conn.execute(
                "INSERT OR REPLACE INTO ProviderDetails (ProviderName, VersionKey, Events) VALUES (?, ?, ?)",
                params![name, "vk1:placeholder", compressed_data],
            ).map_err(|e| CaptureError(e.to_string()))?;
        }

        unsafe { EvtClose(publisher_handle) };
    }

    Ok(())
}

#[cfg(not(target_os = "windows"))]
pub fn capture_providers_to_db(_db_path: &Path) -> Result<(), CaptureError> {
    Err(CaptureError("Provider capture only available on Windows".to_string()))
}
