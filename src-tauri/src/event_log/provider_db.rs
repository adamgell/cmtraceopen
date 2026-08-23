//! Reading captured provider metadata out of an EventLogExpert provider database.
//!
//! The rendering half lives in `cmtraceopen_parser::provider`, which is pure and works on every
//! platform. This is the host half: it opens the SQLite file, decompresses the payloads, and hands
//! typed metadata across. Keeping SQLite and gzip out of the parser crate is what lets the same
//! rendering run in a wasm build.
//!
//! Format, reverse engineered from a database built on Windows 11 (full spec in issue #539):
//!
//! ```text
//! CREATE TABLE "ProviderDetails" (
//!   "ProviderName" TEXT COLLATE NOCASE, "VersionKey" TEXT,
//!   "Events" BLOB, "Keywords" BLOB, "Maps" BLOB, "Messages" BLOB,
//!   "Opcodes" BLOB, "Parameters" BLOB, "Tasks" BLOB,
//!   PRIMARY KEY ("ProviderName","VersionKey"))
//!
//! Captured level maps are carried in the canonical `Maps` JSON BLOB under a `levels` member;
//! databases produced by EventLogExpert without that member read as having no named levels.
//!
//! Every BLOB is gzip-compressed JSON. A real database holds about 1,180 providers in 16 MB, so
//! rows are read on demand and cached rather than loaded eagerly.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::io::{Read, Write};
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use cmtraceopen_parser::provider::ProviderMetadata;
use flate2::read::GzDecoder;
use flate2::write::GzEncoder;
use flate2::Compression;
use rusqlite::{Connection, OpenFlags};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// What a database contributed, so an operator can see coverage rather than guess at it.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ProviderDbInfo {
    /// Path that was opened.
    pub path: String,
    /// Number of provider rows.
    pub provider_count: u64,
    /// Windows build the metadata was captured from, when the rows agree on one.
    pub source_os_build: Option<u32>,
}

/// One provider database that could not be opened while scanning a directory.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ProviderDbLoadFailure {
    pub path: String,
    pub reason: String,
}

/// Coverage returned by a provider-directory load.
///
/// Valid databases remain registered even when one or more siblings fail, while the failures stay
/// attached to the IPC result instead of being reduced to a warning and a misleading clean success.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ProviderDbLoadOutcome {
    pub loaded: Vec<ProviderDbInfo>,
    pub failures: Vec<ProviderDbLoadFailure>,
}
pub(crate) fn packaged_provider_load_is_complete(outcome: &ProviderDbLoadOutcome) -> bool {
    !outcome.loaded.is_empty() && outcome.failures.is_empty()
}

/// Decompresses one gzip JSON payload into `T`.
///
/// An empty BLOB is a legitimately empty section rather than a fault, so it deserializes to the
/// type's default instead of erroring.
/// Largest decompressed provider payload accepted from a database.
///
/// The biggest real provider in a 15.8 MB capture inflates to well under a megabyte, so 64 MB
/// refuses only what could not be a genuine payload.
const MAX_PROVIDER_PAYLOAD_BYTES: u64 = 64 * 1024 * 1024;
const MAX_PROVIDER_ROWS: u64 = 100_000;

fn inflate_json<T: serde::de::DeserializeOwned + Default>(blob: &[u8]) -> Result<T, String> {
    if blob.is_empty() {
        return Ok(T::default());
    }
    // Capped. These databases are evidence supplied by someone else, and an unbounded inflate lets
    // a small blob expand to gigabytes and exhaust memory before serde_json ever sees it. The cap
    // is far above any real provider payload, so it refuses only what could not be genuine.
    let mut decoder = GzDecoder::new(blob).take(MAX_PROVIDER_PAYLOAD_BYTES + 1);
    let mut json = String::new();
    decoder
        .read_to_string(&mut json)
        .map_err(|error| format!("provider payload is not valid gzip: {error}"))?;
    if json.len() as u64 > MAX_PROVIDER_PAYLOAD_BYTES {
        return Err(format!(
            "provider payload inflates past {MAX_PROVIDER_PAYLOAD_BYTES} bytes and was refused"
        ));
    }
    if json.trim().is_empty() {
        return Ok(T::default());
    }
    serde_json::from_str(&json)
        .map_err(|error| format!("provider payload is not valid JSON: {error}"))
}

/// An open provider database.
///
/// Debug deliberately reports only the summary; the connection has no useful representation.
pub struct ProviderDb {
    connection: Connection,
    info: ProviderDbInfo,
    has_capture_state: bool,
}

impl std::fmt::Debug for ProviderDb {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ProviderDb")
            .field("info", &self.info)
            .finish_non_exhaustive()
    }
}

impl ProviderDb {
    /// Opens `path` read-only.
    ///
    /// Read-only matters: these databases are evidence supplied by someone else, and opening them
    /// writable would let SQLite journal into the directory they arrived in.
    pub fn open(path: &Path) -> Result<Self, String> {
        let database_size = std::fs::metadata(path)
            .map_err(|error| format!("cannot stat provider database {}: {error}", path.display()))?
            .len();
        if database_size > MAX_PROVIDER_DATABASE_BYTES {
            return Err(format!(
                "provider database exceeds the {MAX_PROVIDER_DATABASE_BYTES}-byte import/export limit"
            ));
        }
        let connection = Connection::open_with_flags(
            path,
            // Read-only, and deliberately without SQLITE_OPEN_URI. With that flag any path
            // starting with "file:" is parsed as a URI and its parameters honoured, including
            // vfs=. These paths come from scanning a directory the operator pointed at, so a
            // file dropped there could otherwise choose how SQLite opens it.
            OpenFlags::SQLITE_OPEN_READ_ONLY,
        )
        .map_err(|error| format!("cannot open provider database {}: {error}", path.display()))?;

        // SQLite integers are signed 64-bit, so rusqlite offers no u64 conversion. Counting rows
        // cannot be negative, so widening from i64 is safe and keeps the public type unsigned.
        let provider_count: i64 = connection
            .query_row("SELECT COUNT(*) FROM ProviderDetails", [], |row| row.get(0))
            .map_err(|error| {
                format!(
                    "{} does not look like a provider database: {error}",
                    path.display()
                )
            })?;
        if provider_count < 0 || provider_count as u64 > MAX_PROVIDER_ROWS {
            return Err(format!(
                "{} contains too many provider rows (maximum is {MAX_PROVIDER_ROWS})",
                path.display()
            ));
        }

        // Only meaningful when the whole database came from one capture, which is the normal case;
        // a merged database reports nothing rather than an arbitrary one of several builds. One
        // query answers both halves: MIN and MAX agree exactly when there is a single build.
        let (low, high): (Option<u32>, Option<u32>) = connection
            .query_row(
                "SELECT MIN(SourceOsBuild), MAX(SourceOsBuild) FROM ProviderDetails",
                [],
                |row| Ok((row.get::<_, Option<u32>>(0)?, row.get::<_, Option<u32>>(1)?)),
            )
            .map_err(|error| {
                format!(
                    "{} has an invalid ProviderDetails.SourceOsBuild column in provider database: {error}",
                    path.display()
                )
            })?;
        let source_os_build = match (low, high) {
            (Some(low), Some(high)) if low == high => Some(low),
            _ => None,
        };
        let has_capture_state: bool = connection
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM sqlite_master \
                 WHERE type = 'table' AND name = 'ProviderCaptureState')",
                [],
                |row| row.get(0),
            )
            .map_err(|error| format!("cannot inspect provider capture state: {error}"))?;
        Ok(Self {
            info: ProviderDbInfo {
                path: path.display().to_string(),
                provider_count: provider_count as u64,
                source_os_build,
            },
            connection,
            has_capture_state,
        })
    }

    /// Summary of what this database holds.
    pub fn info(&self) -> &ProviderDbInfo {
        &self.info
    }
    fn provider_names(&self) -> Result<BTreeSet<String>, String> {
        let mut statement = self
            .connection
            .prepare("SELECT DISTINCT ProviderName FROM ProviderDetails")
            .map_err(|error| format!("cannot prepare provider-name query: {error}"))?;
        let names = statement
            .query_map([], |row| row.get::<_, String>(0))
            .map_err(|error| format!("cannot read provider names: {error}"))?
            .collect::<Result<BTreeSet<_>, _>>()
            .map_err(|error| format!("cannot read provider name: {error}"))?;
        Ok(names)
    }

    /// Reads every `ProviderDetails` row in deterministic order.
    ///
    /// This is intentionally separate from [`Self::provider`], whose historical API chooses one
    /// row for rendering. Distribution and export callers must not silently collapse distinct
    /// `VersionKey` values.
    pub fn rows(&self) -> Result<Vec<CapturedProviderMetadata>, String> {
        self.rows_for(None)
    }

    /// Reads every captured version for one provider name.
    pub fn provider_versions(
        &self,
        provider_name: &str,
    ) -> Result<Vec<CapturedProviderMetadata>, String> {
        self.rows_for(Some(provider_name))
    }

    fn rows_for(
        &self,
        provider_name: Option<&str>,
    ) -> Result<Vec<CapturedProviderMetadata>, String> {
        let query = if self.has_capture_state {
            "SELECT details.ProviderName, details.VersionKey, details.Events, details.Messages,
                    details.Tasks, details.Keywords, details.Opcodes, details.Maps,
                    details.Parameters, details.SourceOsBuild, state.UnavailableCategories
             FROM ProviderDetails AS details
             LEFT JOIN ProviderCaptureState AS state
               ON state.ProviderName = details.ProviderName
              AND ((state.VersionKey = details.VersionKey)
                   OR (state.VersionKey IS NULL AND details.VersionKey IS NULL))
             WHERE (?1 IS NULL OR details.ProviderName = ?1)
             ORDER BY details.ProviderName COLLATE NOCASE ASC, details.ProviderName ASC,
                      details.SourceOsBuild DESC, details.VersionKey ASC, details.rowid ASC"
        } else {
            "SELECT details.ProviderName, details.VersionKey, details.Events, details.Messages,
                    details.Tasks, details.Keywords, details.Opcodes, details.Maps,
                    details.Parameters, details.SourceOsBuild, NULL
             FROM ProviderDetails AS details
             WHERE (?1 IS NULL OR details.ProviderName = ?1)
             ORDER BY details.ProviderName COLLATE NOCASE ASC, details.ProviderName ASC,
                      details.SourceOsBuild DESC, details.VersionKey ASC, details.rowid ASC"
        };
        let mut statement = self
            .connection
            .prepare(query)
            .map_err(|error| format!("cannot prepare provider query: {error}"))?;

        let rows = statement
            .query_map([provider_name], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, Option<String>>(1)?,
                    row.get::<_, Option<Vec<u8>>>(2)?.unwrap_or_default(),
                    row.get::<_, Option<Vec<u8>>>(3)?.unwrap_or_default(),
                    row.get::<_, Option<Vec<u8>>>(4)?.unwrap_or_default(),
                    row.get::<_, Option<Vec<u8>>>(5)?.unwrap_or_default(),
                    row.get::<_, Option<Vec<u8>>>(6)?.unwrap_or_default(),
                    row.get::<_, Option<Vec<u8>>>(7)?.unwrap_or_default(),
                    row.get::<_, Option<Vec<u8>>>(8)?.unwrap_or_default(),
                    row.get::<_, Option<u32>>(9)?,
                    row.get::<_, Option<Vec<u8>>>(10)?,
                ))
            })
            .map_err(|error| format!("cannot read provider rows: {error}"))?;
        let raw_rows = rows
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| format!("cannot read provider row: {error}"))?;
        drop(statement);

        raw_rows
            .into_iter()
            .map(
                |(
                    provider_name,
                    version_key,
                    events,
                    messages,
                    tasks,
                    keywords,
                    opcodes,
                    maps,
                    parameters,
                    source_os_build,
                    unavailable_categories,
                )| {
                    let levels = levels_from_maps(&maps)?;
                    let mut unavailable_categories: BTreeSet<String> = unavailable_categories
                        .as_deref()
                        .map(inflate_json)
                        .transpose()?
                        .unwrap_or_default();
                    if unavailable_categories.is_empty() {
                        unavailable_categories =
                            unavailable_categories_from_parameters(&parameters)?;
                    }
                    let version_key = version_key.unwrap_or_default();
                    Ok(CapturedProviderMetadata {
                        version_key,
                        metadata: ProviderMetadata {
                            provider_name,
                            events: inflate_json(&events)?,
                            messages: inflate_json(&messages)?,
                            levels,
                            tasks: inflate_json(&tasks)?,
                            keywords: inflate_json(&keywords)?,
                            opcodes: inflate_json(&opcodes)?,
                            unavailable_categories,
                            source_os_build,
                        },
                    })
                },
            )
            .collect()
    }

    /// Loads the best matching metadata row for rendering.
    ///
    /// Rows remain available through [`Self::rows`] and [`Self::provider_versions`]; this
    /// convenience method retains the original highest-build selection used by event rendering.
    pub fn provider(&self, name: &str) -> Result<Option<ProviderMetadata>, String> {
        Ok(self
            .provider_versions(name)?
            .into_iter()
            .next()
            .map(|captured| captured.metadata))
    }
}
/// The `ProviderDetails` schema the reader and writer share, observed on a Windows 11 capture and
/// matching EventLogExpert's database.
const PROVIDER_DETAILS_SCHEMA: &str = r#"CREATE TABLE IF NOT EXISTS "ProviderDetails" (
    "ProviderName" TEXT COLLATE NOCASE NOT NULL,
    "VersionKey" TEXT NOT NULL,
    "Events" BLOB NOT NULL, "Keywords" BLOB NOT NULL, "Maps" BLOB NOT NULL,
    "Messages" BLOB NOT NULL, "Opcodes" BLOB NOT NULL, "Parameters" BLOB NOT NULL,
    "Tasks" BLOB NOT NULL, "SourceOsBuild" INTEGER,
    "ResolvedFromOwningPublisher" TEXT,
    "SourceOsRevision" INTEGER, "SourceOsEdition" TEXT,
    "SourceOsDisplayVersion" TEXT, "MessageFileVersion" TEXT,
    PRIMARY KEY ("ProviderName","VersionKey"));
CREATE TABLE IF NOT EXISTS "ProviderCaptureState" (
    "ProviderName" TEXT COLLATE NOCASE NOT NULL,
    "VersionKey" TEXT NOT NULL,
    "UnavailableCategories" BLOB NOT NULL,
    PRIMARY KEY ("ProviderName","VersionKey")); "#;

/// Serializes `value` to JSON and gzip-compresses it, the way EventLogExpert stores each section.
fn gzip_json<T: Serialize>(value: &T) -> Result<Vec<u8>, String> {
    let json = serde_json::to_vec(value)
        .map_err(|error| format!("cannot serialize provider metadata: {error}"))?;
    if json.len() as u64 > MAX_PROVIDER_PAYLOAD_BYTES {
        return Err(format!(
            "provider metadata section exceeds the {MAX_PROVIDER_PAYLOAD_BYTES}-byte limit"
        ));
    }
    let mut encoder = GzEncoder::new(Vec::new(), Compression::fast());
    encoder
        .write_all(&json)
        .map_err(|error| format!("cannot compress provider metadata: {error}"))?;
    encoder
        .finish()
        .map_err(|error| format!("cannot finish compressing provider metadata: {error}"))
}
fn levels_from_maps(blob: &[u8]) -> Result<BTreeMap<String, String>, String> {
    let maps: serde_json::Value = inflate_json(blob)?;
    let parse_values = |values: &serde_json::Value| -> Result<BTreeMap<String, String>, String> {
        if let Some(entries) = values.as_array() {
            let mut levels = BTreeMap::new();
            for entry in entries {
                let value = entry
                    .get("Value")
                    .or_else(|| entry.get("value"))
                    .ok_or_else(|| "provider level entry is missing Value".to_string())?;
                let name = entry
                    .get("Name")
                    .or_else(|| entry.get("name"))
                    .and_then(serde_json::Value::as_str)
                    .ok_or_else(|| "provider level entry is missing Name".to_string())?;
                let key = match value {
                    serde_json::Value::Number(number) => number
                        .as_u64()
                        .and_then(|number| u32::try_from(number).ok())
                        .or_else(|| {
                            number
                                .as_i64()
                                .and_then(|number| u32::try_from(number).ok())
                        })
                        .ok_or_else(|| {
                            "provider level entry Value is outside the UInt32 range".to_string()
                        })?
                        .to_string(),
                    serde_json::Value::String(raw) => raw
                        .parse::<u32>()
                        .map(|number| number.to_string())
                        .map_err(|_| "provider level entry Value is not a UInt32".to_string())?,
                    _ => return Err("provider level entry Value is not a UInt32".to_string()),
                };
                // ValueMapDefinition resolves the first matching entry. Preserve that
                // behavior when the portable model cannot retain duplicate keys.
                levels.entry(key).or_insert_with(|| name.to_string());
            }
            return Ok(levels);
        }
        if let Some(entries) = values.as_object() {
            let mut levels = BTreeMap::new();
            for (raw_key, value) in entries {
                let key = raw_key
                    .parse::<u32>()
                    .map(|number| number.to_string())
                    .map_err(|_| "provider level map key is not a UInt32".to_string())?;
                let name = value
                    .as_str()
                    .ok_or_else(|| "provider level map value is not a string".to_string())?;
                levels.entry(key).or_insert_with(|| name.to_string());
            }
            return Ok(levels);
        }
        Err("provider level values are not a map or entries array".to_string())
    };
    if let Some(levels) = maps.get("levels") {
        if let Some(values) = levels.get("Entries").or_else(|| levels.get("Values")) {
            return parse_values(values);
        }
        return parse_values(levels);
    }
    if let Some(definitions) = maps
        .get("ValueMapDefinition")
        .and_then(serde_json::Value::as_object)
    {
        if let Some(levels) = definitions.get("levels") {
            let values = levels.get("Values").unwrap_or(levels);
            return parse_values(values);
        }
    }
    if let Some(definitions) = maps
        .get("ValueMapDefinition")
        .and_then(serde_json::Value::as_array)
    {
        for definition in definitions {
            if definition.get("Name").and_then(serde_json::Value::as_str) == Some("levels") {
                if let Some(values) = definition.get("Values") {
                    return parse_values(values);
                }
            }
        }
    }
    Ok(BTreeMap::new())
}
fn unavailable_categories_from_parameters(blob: &[u8]) -> Result<BTreeSet<String>, String> {
    let parameters: serde_json::Value = inflate_json(blob)?;
    parameters
        .get("unavailableCategories")
        .cloned()
        .map(serde_json::from_value)
        .transpose()
        .map_err(|error| format!("provider unavailable categories are not a set: {error}"))?
        .map_or_else(|| Ok(BTreeSet::new()), Ok)
}

/// Provider metadata captured for one concrete provider version.
///
/// The version key is part of the database's composite identity. It must come from the capture
/// walk; deriving it from the source OS build would collapse distinct provider definitions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapturedProviderMetadata {
    pub metadata: ProviderMetadata,
    pub version_key: String,
}
/// Writes captured provider metadata to a new database in EventLogExpert's schema.
///
/// The destination is built beside the requested path and renamed only after the SQLite
/// transaction commits. A failed capture therefore cannot leave a half-written database in place.
pub fn write_provider_database(
    path: &Path,
    providers: &[CapturedProviderMetadata],
) -> Result<usize, String> {
    validate_captured_providers(providers)?;
    let temporary = temporary_path(path, "write")?;
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options.mode(0o600);
    let temporary_file = options.open(&temporary).map_err(|error| {
        format!(
            "cannot create provider database staging file {}: {error}",
            temporary.display()
        )
    })?;
    drop(temporary_file);
    let result = (|| {
        write_provider_database_inner(&temporary, providers)?;
        replace_file(&temporary, path)?;
        Ok(providers.len())
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&temporary);
    }
    result
}

fn validate_captured_providers(providers: &[CapturedProviderMetadata]) -> Result<(), String> {
    if providers.is_empty() {
        return Err("cannot write provider database without captured providers".to_string());
    }
    if providers.len() as u64 > MAX_PROVIDER_ROWS {
        return Err(format!(
            "cannot write more than {MAX_PROVIDER_ROWS} provider rows"
        ));
    }
    let mut identities = BTreeSet::new();
    for captured in providers {
        if captured.version_key.is_empty() {
            return Err(format!(
                "provider {} is missing its captured version key",
                captured.metadata.provider_name
            ));
        }
        if captured.metadata.provider_name.is_empty() {
            return Err("cannot write a provider row without a provider name".to_string());
        }
        let identity = (
            captured.metadata.provider_name.to_ascii_lowercase(),
            captured.version_key.clone(),
        );
        if !identities.insert(identity) {
            return Err(format!(
                "duplicate provider row {} version {}",
                captured.metadata.provider_name, captured.version_key
            ));
        }
    }
    Ok(())
}

fn write_provider_database_inner(
    path: &Path,
    providers: &[CapturedProviderMetadata],
) -> Result<(), String> {
    let mut connection = Connection::open(path).map_err(|error| {
        format!(
            "cannot create provider database {}: {error}",
            path.display()
        )
    })?;
    connection
        .execute_batch(PROVIDER_DETAILS_SCHEMA)
        .map_err(|error| format!("cannot create provider database schema: {error}"))?;
    let transaction = connection
        .transaction()
        .map_err(|error| format!("cannot begin provider database transaction: {error}"))?;
    transaction
        .execute("DELETE FROM ProviderDetails", [])
        .map_err(|error| format!("cannot clear provider database: {error}"))?;
    transaction
        .execute("DELETE FROM ProviderCaptureState", [])
        .map_err(|error| format!("cannot clear provider capture state: {error}"))?;
    for captured in providers {
        let metadata = &captured.metadata;
        let events = gzip_json(&metadata.events)?;
        let keywords = gzip_json(&metadata.keywords)?;
        let mut level_entries = Vec::with_capacity(metadata.levels.len());
        for (value, name) in &metadata.levels {
            let parsed_value = value
                .parse::<u32>()
                .map_err(|_| format!("provider level key {value:?} is not a UInt32"))?;
            level_entries.push(serde_json::json!({
                "Value": parsed_value,
                "Name": name,
            }));
        }
        let maps = gzip_json(&serde_json::json!({
            "levels": {
                "Entries": level_entries,
                "IsBitMap": false
            }
        }))?;
        let messages = gzip_json(&metadata.messages)?;
        let opcodes = gzip_json(&metadata.opcodes)?;
        let tasks = gzip_json(&metadata.tasks)?;
        let parameters = gzip_json(&Vec::<cmtraceopen_parser::provider::ProviderMessage>::new())?;
        transaction
            .execute(
                r#"INSERT INTO ProviderDetails
                   (ProviderName, VersionKey, Events, Keywords, Maps, Messages, Opcodes,
                    Parameters, Tasks, SourceOsBuild)
                   VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)"#,
                rusqlite::params![
                    metadata.provider_name,
                    &captured.version_key,
                    events,
                    keywords,
                    maps,
                    messages,
                    opcodes,
                    parameters,
                    tasks,
                    metadata.source_os_build,
                ],
            )
            .map_err(|error| {
                format!(
                    "cannot insert provider {} version {}: {error}",
                    metadata.provider_name, captured.version_key
                )
            })?;
        let unavailable_categories = gzip_json(&metadata.unavailable_categories)?;
        transaction
            .execute(
                "INSERT INTO ProviderCaptureState \
                 (ProviderName, VersionKey, UnavailableCategories) VALUES (?1, ?2, ?3)",
                rusqlite::params![
                    &metadata.provider_name,
                    &captured.version_key,
                    unavailable_categories
                ],
            )
            .map_err(|error| {
                format!(
                    "cannot insert provider capture state {} version {}: {error}",
                    metadata.provider_name, captured.version_key
                )
            })?;
    }
    transaction
        .commit()
        .map_err(|error| format!("cannot commit provider database transaction: {error}"))
}

/// Copies a validated EventLogExpert provider database to `destination`.
///
/// Copying the SQLite file rather than reconstructing rows preserves every canonical and nullable
/// column, including fields not needed by the renderer. The copy is bounded and published by a
/// same-directory rename, so import/export never exposes a partial file.
pub fn export_provider_database(
    source: &Path,
    destination: &Path,
) -> Result<ProviderDbInfo, String> {
    let source_db = ProviderDb::open(source)?;
    if same_file(source, destination) {
        return Ok(source_db.info().clone());
    }
    let temporary = temporary_path(destination, "export")?;
    let mut temporary_created = false;
    let result = (|| {
        let source_file = std::fs::File::open(source).map_err(|error| {
            format!(
                "cannot read provider database {}: {error}",
                source.display()
            )
        })?;
        let size = source_file
            .metadata()
            .map_err(|error| {
                format!(
                    "cannot stat provider database {}: {error}",
                    source.display()
                )
            })?
            .len();
        if size > MAX_PROVIDER_DATABASE_BYTES {
            return Err(format!(
                "provider database exceeds the {MAX_PROVIDER_DATABASE_BYTES}-byte import/export limit"
            ));
        }
        let mut input = source_file.take(MAX_PROVIDER_DATABASE_BYTES + 1);
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        options.mode(0o600);
        let mut output = options.open(&temporary).map_err(|error| {
            format!(
                "cannot create provider export {}: {error}",
                temporary.display()
            )
        })?;
        temporary_created = true;
        let copied = std::io::copy(&mut input, &mut output)
            .map_err(|error| format!("cannot copy provider database: {error}"))?;
        if copied > MAX_PROVIDER_DATABASE_BYTES {
            return Err(format!(
                "provider database exceeds the {MAX_PROVIDER_DATABASE_BYTES}-byte import/export limit"
            ));
        }
        output
            .sync_all()
            .map_err(|error| format!("cannot flush provider export: {error}"))?;
        drop(output);
        let exported_info = {
            let exported = ProviderDb::open(&temporary)?;
            if exported.info().provider_count != source_db.info().provider_count {
                return Err("provider export row count changed during copy".to_string());
            }
            exported.info().clone()
        };
        replace_file(&temporary, destination)?;
        Ok(exported_info)
    })();
    if result.is_err() && temporary_created {
        let _ = std::fs::remove_file(&temporary);
    }
    result
}

const MAX_PROVIDER_DATABASE_BYTES: u64 = 512 * 1024 * 1024;

fn temporary_path(path: &Path, operation: &str) -> Result<PathBuf, String> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    std::fs::create_dir_all(parent).map_err(|error| {
        format!(
            "cannot create provider database directory {}: {error}",
            parent.display()
        )
    })?;
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| {
            format!(
                "provider database path has no valid file name: {}",
                path.display()
            )
        })?;
    static NEXT_TEMPORARY: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let nonce = NEXT_TEMPORARY.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    Ok(parent.join(format!(
        ".{file_name}.cmtraceopen-{operation}-{}-{nonce}.tmp",
        std::process::id()
    )))
}

#[cfg(not(target_os = "windows"))]
fn replace_file(source: &Path, destination: &Path) -> Result<(), String> {
    std::fs::rename(source, destination).map_err(|error| {
        format!(
            "cannot publish provider database {} as {}: {error}",
            source.display(),
            destination.display()
        )
    })
}

#[cfg(target_os = "windows")]
fn replace_file(source: &Path, destination: &Path) -> Result<(), String> {
    use std::iter::once;
    use std::os::windows::ffi::OsStrExt;
    use windows::core::PCWSTR;
    use windows::Win32::Storage::FileSystem::{
        MoveFileExW, MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH,
    };

    let source_wide: Vec<u16> = source.as_os_str().encode_wide().chain(once(0)).collect();
    let destination_wide: Vec<u16> = destination
        .as_os_str()
        .encode_wide()
        .chain(once(0))
        .collect();
    unsafe {
        MoveFileExW(
            PCWSTR(source_wide.as_ptr()),
            PCWSTR(destination_wide.as_ptr()),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
        )
    }
    .map_err(|error| {
        format!(
            "cannot publish provider database {} as {}: {error}",
            source.display(),
            destination.display()
        )
    })
}

fn same_file(source: &Path, destination: &Path) -> bool {
    if source == destination {
        return true;
    }
    match (
        std::fs::canonicalize(source),
        std::fs::canonicalize(destination),
    ) {
        (Ok(source), Ok(destination)) => source == destination,
        _ => false,
    }
}

/// Relative location used by packaged builds for a curated provider database.
pub const PACKAGED_PROVIDER_DATABASE_DIRECTORY: &str = "provider-db";
/// Manifest beside the packaged database. It records whether provenance is available; an absent
/// Windows capture must never be represented by an empty or synthetic database.
pub const PACKAGED_PROVIDER_MANIFEST_FILE: &str = "provider-manifest.json";

const REQUIRED_PACKAGED_PROVIDER_FAMILIES: [&str; 7] = [
    "MDM",
    "Autopilot",
    "ESP",
    "AAD",
    "ConfigMgr client",
    "AppX",
    "Windows Update",
];

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PackagedProviderDatabase {
    file: String,
    source_windows_build: u32,
    sha256: String,
    provider_count: u64,
    #[serde(default)]
    providers: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PackagedProviderManifest {
    schema_version: u32,
    status: String,
    reason: String,
    #[serde(default)]
    provider_families: Vec<String>,
    #[serde(default)]
    source_windows_builds: Vec<u32>,
    #[serde(default)]
    provider_version: Option<String>,
    databases: Option<Vec<PackagedProviderDatabase>>,
}

const PACKAGED_SHA256_HEX_LENGTH: usize = 64;

fn is_lower_sha256(value: &str) -> bool {
    value.len() == PACKAGED_SHA256_HEX_LENGTH
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

fn sha256_file(path: &Path) -> Result<String, String> {
    let size = std::fs::metadata(path)
        .map_err(|error| {
            format!(
                "cannot stat packaged provider database {}: {error}",
                path.display()
            )
        })?
        .len();
    if size > MAX_PROVIDER_DATABASE_BYTES {
        return Err(format!(
            "packaged provider database {} exceeds the {MAX_PROVIDER_DATABASE_BYTES}-byte limit",
            path.display()
        ));
    }
    let mut file = std::fs::File::open(path).map_err(|error| {
        format!(
            "cannot read packaged provider database {}: {error}",
            path.display()
        )
    })?;
    let mut hasher = Sha256::new();
    let mut bytes_read = 0u64;
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer).map_err(|error| {
            format!(
                "cannot read packaged provider database {}: {error}",
                path.display()
            )
        })?;
        if read == 0 {
            break;
        }
        bytes_read = bytes_read.saturating_add(read as u64);
        if bytes_read > MAX_PROVIDER_DATABASE_BYTES {
            return Err(format!(
                "packaged provider database {} exceeds the {MAX_PROVIDER_DATABASE_BYTES}-byte limit",
                path.display()
            ));
        }
        hasher.update(&buffer[..read]);
    }
    Ok(hasher
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect())
}

fn validate_packaged_provider_database(
    directory: &Path,
    entry: &PackagedProviderDatabase,
) -> Result<(), String> {
    if entry.file.is_empty()
        || entry.file == "."
        || entry.file == ".."
        || entry.file.bytes().any(|byte| matches!(byte, b'/' | b'\\'))
        || Path::new(&entry.file)
            .file_name()
            .and_then(|name| name.to_str())
            != Some(entry.file.as_str())
        || !Path::new(&entry.file)
            .extension()
            .and_then(|extension| extension.to_str())
            .is_some_and(|extension| extension.eq_ignore_ascii_case("db"))
    {
        return Err(format!(
            "packaged provider manifest declares unsafe database filename {:?}",
            entry.file
        ));
    }
    if !is_lower_sha256(&entry.sha256) {
        return Err(format!(
            "packaged provider manifest database {} has an invalid lowercase sha256",
            entry.file
        ));
    }
    let provider_names: BTreeSet<&str> = entry.providers.iter().map(String::as_str).collect();
    if provider_names.len() != entry.providers.len()
        || entry
            .providers
            .iter()
            .any(|provider| provider.trim().is_empty())
    {
        return Err(format!(
            "packaged provider manifest database {} has inconsistent providers metadata",
            entry.file
        ));
    }

    let path = directory.join(&entry.file);
    let file_type = std::fs::symlink_metadata(&path)
        .map_err(|error| {
            format!(
                "cannot stat packaged provider database {}: {error}",
                path.display()
            )
        })?
        .file_type();
    if !file_type.is_file() {
        return Err(format!(
            "packaged provider database {} is not a regular file",
            path.display()
        ));
    }
    let actual_sha256 = sha256_file(&path)?;
    if actual_sha256 != entry.sha256 {
        return Err(format!(
            "packaged provider database {} sha256 mismatch: manifest {}, actual {}",
            path.display(),
            entry.sha256,
            actual_sha256
        ));
    }
    let database = ProviderDb::open(&path)?;
    let info = database.info();
    if info.provider_count != entry.provider_count {
        return Err(format!(
            "packaged provider database {} providerCount mismatch: manifest {}, actual {}",
            path.display(),
            entry.provider_count,
            info.provider_count
        ));
    }
    if info.source_os_build != Some(entry.source_windows_build) {
        return Err(format!(
            "packaged provider database {} sourceWindowsBuild mismatch: manifest {}, actual {:?}",
            path.display(),
            entry.source_windows_build,
            info.source_os_build
        ));
    }
    let actual_provider_names = database.provider_names()?;
    let expected_provider_names: BTreeSet<String> = entry.providers.iter().cloned().collect();
    if actual_provider_names != expected_provider_names {
        return Err(format!(
            "packaged provider database {} providers do not match manifest",
            path.display()
        ));
    }
    Ok(())
}

/// Finds the packaged provider directory without inventing coverage when no real Windows capture is
/// checked in.
pub fn packaged_provider_directory(resource_dir: &Path) -> Result<PathBuf, String> {
    let directory = resource_dir.join(PACKAGED_PROVIDER_DATABASE_DIRECTORY);
    if !directory.is_dir() {
        return Err(format!(
            "no curated provider database is packaged at {}; a real Windows-captured \
             EventLogExpert ProviderDetails database is required before packaging provider coverage",
            directory.display()
        ));
    }
    let manifest_path = directory.join(PACKAGED_PROVIDER_MANIFEST_FILE);
    let manifest_text = std::fs::read_to_string(&manifest_path).map_err(|error| {
        format!(
            "packaged provider manifest {} is unavailable: {error}; cannot claim \
             EventLogExpert ProviderDetails coverage",
            manifest_path.display()
        )
    })?;
    let manifest: PackagedProviderManifest =
        serde_json::from_str(&manifest_text).map_err(|error| {
            format!(
                "packaged provider manifest {} is invalid: {error}; cannot claim \
                 EventLogExpert ProviderDetails coverage",
                manifest_path.display()
            )
        })?;
    if manifest.schema_version != 1 {
        return Err(format!(
            "packaged provider manifest {} has unsupported schemaVersion {}; cannot claim \
             EventLogExpert ProviderDetails coverage",
            manifest_path.display(),
            manifest.schema_version
        ));
    }
    if manifest.status != "available" {
        let families = if manifest.provider_families.is_empty() {
            "none declared".to_string()
        } else {
            manifest.provider_families.join(", ")
        };
        return Err(format!(
            "packaged provider manifest {} reports status {}: {}; required provider families: \
             {families}; a real Windows-captured EventLogExpert ProviderDetails database is \
             required before packaging provider coverage",
            manifest_path.display(),
            manifest.status,
            manifest.reason
        ));
    }
    let families: BTreeSet<&str> = manifest
        .provider_families
        .iter()
        .map(String::as_str)
        .collect();
    if families.len() != manifest.provider_families.len()
        || families.len() != REQUIRED_PACKAGED_PROVIDER_FAMILIES.len()
        || REQUIRED_PACKAGED_PROVIDER_FAMILIES
            .iter()
            .any(|family| !families.contains(family))
        || manifest
            .provider_families
            .iter()
            .any(|family| !REQUIRED_PACKAGED_PROVIDER_FAMILIES.contains(&family.as_str()))
    {
        return Err(format!(
            "packaged provider manifest {} has invalid providerFamilies; expected exactly: {}; cannot claim \
             EventLogExpert ProviderDetails coverage",
            manifest_path.display(),
            REQUIRED_PACKAGED_PROVIDER_FAMILIES.join(", ")
        ));
    }
    let source_builds: BTreeSet<u32> = manifest.source_windows_builds.iter().copied().collect();
    if source_builds.len() != manifest.source_windows_builds.len()
        || source_builds.is_empty()
        || manifest
            .provider_version
            .as_deref()
            .is_none_or(|value| value.trim().is_empty())
    {
        return Err(format!(
            "packaged provider manifest {} is missing unique sourceWindowsBuilds or providerVersion provenance; \
             cannot claim EventLogExpert ProviderDetails coverage",
            manifest_path.display()
        ));
    }

    let Some(databases) = manifest.databases.as_ref() else {
        return Err(format!(
            "packaged provider manifest {} is missing databases integrity metadata; cannot claim \
             EventLogExpert ProviderDetails coverage",
            manifest_path.display()
        ));
    };
    if databases.is_empty() {
        return Err(format!(
            "packaged provider manifest {} declares no databases; cannot claim \
             EventLogExpert ProviderDetails coverage",
            manifest_path.display()
        ));
    }

    let mut declared_files = BTreeSet::new();
    let mut declared_lowercase_files = BTreeSet::new();
    let mut database_builds = BTreeSet::new();
    for database in databases {
        if !declared_files.insert(database.file.clone()) {
            return Err(format!(
                "packaged provider manifest {} declares database {} more than once",
                manifest_path.display(),
                database.file
            ));
        }
        if !declared_lowercase_files.insert(database.file.to_ascii_lowercase()) {
            return Err(format!(
                "packaged provider manifest {} declares case-colliding database filenames",
                manifest_path.display()
            ));
        }
        if !database_builds.insert(database.source_windows_build)
            || !source_builds.contains(&database.source_windows_build)
        {
            return Err(format!(
                "packaged provider manifest {} has duplicate or undeclared sourceWindowsBuild {}",
                manifest_path.display(),
                database.source_windows_build
            ));
        }
    }
    if database_builds != source_builds {
        return Err(format!(
            "packaged provider manifest {} sourceWindowsBuilds do not match database entries",
            manifest_path.display()
        ));
    }

    let mut actual_files = BTreeSet::new();
    let mut actual_lowercase_files = BTreeSet::new();
    for entry in std::fs::read_dir(&directory).map_err(|error| {
        format!(
            "cannot inspect packaged provider directory {}: {error}",
            directory.display()
        )
    })? {
        let entry = entry.map_err(|error| {
            format!(
                "cannot read packaged provider directory entry in {}: {error}",
                directory.display()
            )
        })?;
        let file_name = entry.file_name();
        let file_name = file_name.to_str().ok_or_else(|| {
            format!(
                "packaged provider directory {} contains a non-UTF-8 filename",
                directory.display()
            )
        })?;
        if !Path::new(file_name)
            .extension()
            .and_then(|extension| extension.to_str())
            .is_some_and(|extension| extension.eq_ignore_ascii_case("db"))
        {
            continue;
        }
        if !entry
            .file_type()
            .map_err(|error| {
                format!("cannot inspect packaged provider database {file_name}: {error}")
            })?
            .is_file()
        {
            return Err(format!(
                "packaged provider database {} is not a regular file",
                directory.join(file_name).display()
            ));
        }
        if !actual_lowercase_files.insert(file_name.to_ascii_lowercase()) {
            return Err(format!(
                "packaged provider directory contains case-colliding database filenames near {}",
                file_name
            ));
        }
        actual_files.insert(file_name.to_owned());
    }
    if actual_files != declared_files {
        let missing = declared_files
            .difference(&actual_files)
            .cloned()
            .collect::<Vec<_>>();
        let extra = actual_files
            .difference(&declared_files)
            .cloned()
            .collect::<Vec<_>>();
        return Err(format!(
            "packaged provider database set does not match manifest (missing: {}; undeclared: {})",
            if missing.is_empty() {
                "none".to_string()
            } else {
                missing.join(", ")
            },
            if extra.is_empty() {
                "none".to_string()
            } else {
                extra.join(", ")
            }
        ));
    }
    for database in databases {
        validate_packaged_provider_database(&directory, database).map_err(|error| {
            format!(
                "packaged provider manifest {} failed database validation: {error}",
                manifest_path.display()
            )
        })?;
    }
    Ok(directory)
}

// ── Store ───────────────────────────────────────────────────────────────────

/// Registered provider databases and the metadata read from them.
///
/// Owned by `AppState` rather than held as a process global. A global made every test share one
/// set: `load_directory` clears and replaces it, and cargo runs tests on parallel threads in one
/// process, so two tests registering databases would interfere. It also meant the registration
/// outlived any workspace the operator closed, with no way to reset it.
#[derive(Default)]
pub struct ProviderStore {
    /// Lowercased provider name to metadata, including negative results so a provider absent from
    /// every database is not looked up again for every event that mentions it.
    ///
    /// Behind an `Arc` because a lookup happens once per record. A real provider carries every
    /// event it defines with its description strings, so returning it by value meant a deep clone
    /// per event: up to a hundred thousand of them to render one file.
    /// Behind a `Mutex` so a lookup does not need `&mut self`. Without it the parse path had to
    /// hold a write guard on the whole store for the length of a file, blocking every other reader
    /// just to populate a cache.
    cache: Mutex<HashMap<String, Option<Arc<ProviderMetadata>>>>,
    /// Every captured version row for each provider. Event lookup uses this before applying its
    /// exact-version-then-fallback rule; caching only one row loses definitions from other keys.
    version_cache: Mutex<HashMap<String, Option<Arc<Vec<CapturedProviderMetadata>>>>>,
    /// The registered databases, opened once at registration and reused for every lookup.
    open_databases: Mutex<Vec<ProviderDb>>,
    info: Vec<ProviderDbInfo>,
}

impl ProviderStore {
    /// Registers every `.db` in `directory`, replacing any previously registered set.
    pub fn load_directory(&mut self, directory: &Path) -> Result<ProviderDbLoadOutcome, String> {
        let entries = std::fs::read_dir(directory).map_err(|error| {
            format!(
                "cannot read provider database directory {}: {error}",
                directory.display()
            )
        })?;

        let mut databases: Vec<ProviderDb> = Vec::new();
        let mut info = Vec::new();
        let mut failures: Vec<ProviderDbLoadFailure> = Vec::new();

        let mut paths: Vec<PathBuf> = Vec::new();
        for entry in entries {
            // An enumeration error after the directory opened is recorded, not skipped, matching
            // the map loader. Dropping it lets a partial set look complete.
            match entry {
                Ok(entry) => paths.push(entry.path()),
                Err(error) => failures.push(ProviderDbLoadFailure {
                    path: directory.display().to_string(),
                    reason: format!("cannot read directory entry: {error}"),
                }),
            }
        }
        paths.retain(|path| {
            path.is_file()
                && path
                    .extension()
                    .and_then(|extension| extension.to_str())
                    .is_some_and(|extension| extension.eq_ignore_ascii_case("db"))
        });
        paths.sort();

        for path in paths {
            match ProviderDb::open(&path) {
                Ok(database) => {
                    info.push(database.info().clone());
                    // Kept open. Reopening per lookup also re-ran the schema probe inside open(),
                    // once per registered database for every distinct provider name in a file.
                    databases.push(database);
                }
                // A file that is not a provider database is reported, not fatal: the directory is
                // user-supplied and may hold anything.
                Err(reason) => failures.push(ProviderDbLoadFailure {
                    path: path.display().to_string(),
                    reason,
                }),
            }
        }

        // The locks are taken before anything is published, and a failure aborts rather than
        // continuing. This takes &mut self, so neither lock can be contended and the only failure
        // is poisoning; swallowing it left `info` describing databases that were never opened, so
        // registered() reported coverage that no lookup could deliver.
        let mut open = self
            .open_databases
            .lock()
            .map_err(|_| "provider store lock was poisoned".to_string())?;
        let mut cache = self
            .cache
            .lock()
            .map_err(|_| "provider cache lock was poisoned".to_string())?;
        let mut version_cache = self
            .version_cache
            .lock()
            .map_err(|_| "provider version cache lock was poisoned".to_string())?;
        *open = databases;
        cache.clear();
        version_cache.clear();
        drop(open);
        drop(cache);
        drop(version_cache);
        self.info = info.clone();

        // Reported even when something loaded. Returning only valid files would leave an operator
        // looking at partial provider coverage with no explanation for it.
        for failure in &failures {
            log::warn!(
                "event=provider_db_skipped path=\"{}\" reason=\"{}\"",
                failure.path,
                failure.reason
            );
        }
        Ok(ProviderDbLoadOutcome {
            loaded: info,
            failures,
        })
    }

    /// Metadata for `provider_name`, consulting registered databases in order and caching it.
    ///
    /// Errors are returned rather than treated as an absent provider. A corrupt payload is a
    /// coverage failure, not a metadata miss.
    pub fn provider(&self, provider_name: &str) -> Result<Option<Arc<ProviderMetadata>>, String> {
        let key = provider_name.to_ascii_lowercase();
        if let Some(cached) = self
            .cache
            .lock()
            .map_err(|_| "provider cache lock was poisoned".to_string())?
            .get(&key)
            .cloned()
        {
            return Ok(cached);
        }

        let rows = self.provider_versions_cached(provider_name)?;
        let found = rows
            .as_ref()
            .and_then(|rows| rows.first())
            .map(|captured| Arc::new(captured.metadata.clone()));
        self.cache
            .lock()
            .map_err(|_| "provider cache lock was poisoned".to_string())?
            .insert(key, found.clone());
        Ok(found)
    }

    /// Selects metadata for an event by searching every captured provider/version row.
    ///
    /// An exact event version and captured channel win even when they live in an older row. If the
    /// requested version is absent, the first row defining the event on that channel is the
    /// deterministic fallback.
    pub fn provider_for_event(
        &self,
        provider_name: &str,
        channel: &str,
        event_id: u32,
        version: Option<u32>,
    ) -> Result<Option<Arc<ProviderMetadata>>, String> {
        let Some(rows) = self.provider_versions_cached(provider_name)? else {
            return Ok(None);
        };
        let channel_score =
            |event: &cmtraceopen_parser::provider::ProviderEvent| match event.log_name.as_deref() {
                Some(expected) if expected.eq_ignore_ascii_case(channel) => 2u8,
                None => 1u8,
                _ => 0u8,
            };
        let find_matching = |requested_version: Option<u32>, minimum_score: u8| {
            rows.iter().find(|row| {
                row.metadata.events.iter().any(|event| {
                    event.id == event_id
                        && requested_version.is_none_or(|value| event.version == value)
                        && channel_score(event) >= minimum_score
                })
            })
        };
        let selected = version
            .and_then(|value| find_matching(Some(value), 2))
            .or_else(|| version.and_then(|value| find_matching(Some(value), 1)))
            .or_else(|| find_matching(None, 2))
            .or_else(|| find_matching(None, 1));
        Ok(selected.map(|row| Arc::new(row.metadata.clone())))
    }

    fn provider_versions_cached(
        &self,
        provider_name: &str,
    ) -> Result<Option<Arc<Vec<CapturedProviderMetadata>>>, String> {
        let key = provider_name.to_ascii_lowercase();
        if let Some(cached) = self
            .version_cache
            .lock()
            .map_err(|_| "provider version cache lock was poisoned".to_string())?
            .get(&key)
            .cloned()
        {
            return Ok(cached);
        }

        let open = self
            .open_databases
            .lock()
            .map_err(|_| "provider store lock was poisoned".to_string())?;
        let mut rows = Vec::new();
        for database in open.iter() {
            rows.extend(database.provider_versions(provider_name)?);
        }
        rows.sort_by(|left, right| {
            right
                .metadata
                .source_os_build
                .cmp(&left.metadata.source_os_build)
                .then_with(|| left.version_key.cmp(&right.version_key))
        });
        let found = (!rows.is_empty()).then(|| Arc::new(rows));
        self.version_cache
            .lock()
            .map_err(|_| "provider version cache lock was poisoned".to_string())?
            .insert(key, found.clone());
        Ok(found)
    }

    /// Summary of every registered database.
    pub fn registered(&self) -> Vec<ProviderDbInfo> {
        self.info.clone()
    }
    /// Registers one imported provider database, replacing the current set.
    pub fn load_database(&mut self, path: &Path) -> Result<ProviderDbLoadOutcome, String> {
        let database = ProviderDb::open(path)?;
        let info = database.info().clone();
        let mut open = self
            .open_databases
            .lock()
            .map_err(|_| "provider store lock was poisoned".to_string())?;
        let mut cache = self
            .cache
            .lock()
            .map_err(|_| "provider cache lock was poisoned".to_string())?;
        let mut version_cache = self
            .version_cache
            .lock()
            .map_err(|_| "provider version cache lock was poisoned".to_string())?;
        *open = vec![database];
        cache.clear();
        version_cache.clear();
        self.info = vec![info.clone()];
        Ok(ProviderDbLoadOutcome {
            loaded: vec![info],
            failures: Vec::new(),
        })
    }

    /// Returns every provider/version row from all registered databases.
    pub fn rows(&self) -> Result<Vec<CapturedProviderMetadata>, String> {
        let open = self
            .open_databases
            .lock()
            .map_err(|_| "provider store lock was poisoned".to_string())?;
        let mut rows = Vec::new();
        for database in open.iter() {
            rows.extend(database.rows()?);
        }
        Ok(rows)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::write::GzEncoder;
    use flate2::Compression;
    use std::io::Write;

    fn gzip(json: &str) -> Vec<u8> {
        let mut encoder = GzEncoder::new(Vec::new(), Compression::fast());
        encoder.write_all(json.as_bytes()).expect("compress");
        encoder.finish().expect("finish")
    }

    /// Builds a database with the schema observed on Windows 11.
    fn build_db(path: &Path, providers: &[(&str, u32, &str)]) {
        let connection = Connection::open(path).expect("create");
        connection
            .execute_batch(
                r#"CREATE TABLE "ProviderDetails" (
                     "ProviderName" TEXT COLLATE NOCASE NOT NULL,
                     "VersionKey" TEXT NOT NULL,
                     "Events" BLOB NOT NULL, "Keywords" BLOB NOT NULL, "Maps" BLOB NOT NULL,
                     "Messages" BLOB NOT NULL, "Opcodes" BLOB NOT NULL, "Parameters" BLOB NOT NULL,
                     "Tasks" BLOB NOT NULL, "SourceOsBuild" INTEGER,
                     PRIMARY KEY ("ProviderName","VersionKey"));"#,
            )
            .expect("schema");

        for (index, (name, build, events_json)) in providers.iter().enumerate() {
            connection
                .execute(
                    r#"INSERT INTO ProviderDetails
                       (ProviderName, VersionKey, Events, Keywords, Maps, Messages, Opcodes,
                        Parameters, Tasks, SourceOsBuild)
                       VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)"#,
                    rusqlite::params![
                        name,
                        format!("vk1:{build}:{index}"),
                        gzip(events_json),
                        gzip(r#"{"1":"Error"}"#),
                        gzip(r#"{"2":"Information"}"#),
                        gzip("[]"),
                        gzip(r#"{"11":"Start"}"#),
                        gzip("[]"),
                        gzip(r#"{"1":"Enrollment"}"#),
                        build,
                    ],
                )
                .expect("insert");
        }
    }

    const EVENTS: &str = r#"[{"Id":2,"Version":0,"Description":"Enroll failed: (%1).","Level":2}]"#;

    fn temp_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("cmtraceopen-providerdb-{name}"));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("temp dir");
        dir
    }
    fn copy_checked_in_package(name: &str) -> PathBuf {
        let root = temp_dir(name);
        let source = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("resources")
            .join(PACKAGED_PROVIDER_DATABASE_DIRECTORY);
        let destination = root.join(PACKAGED_PROVIDER_DATABASE_DIRECTORY);
        std::fs::create_dir_all(&destination).expect("provider package directory");
        for file in [
            "cmtraceopen-provider-windows-20348.db",
            "cmtraceopen-provider-windows-26200.db",
            PACKAGED_PROVIDER_MANIFEST_FILE,
        ] {
            std::fs::copy(source.join(file), destination.join(file)).expect("copy package file");
        }
        root
    }

    #[test]
    fn reads_a_provider_and_inflates_its_payloads() {
        let dir = temp_dir("read");
        let path = dir.join("base.db");
        build_db(&path, &[("Test-Provider", 26200, EVENTS)]);

        let database = ProviderDb::open(&path).expect("opens");
        assert_eq!(database.info().provider_count, 1);
        assert_eq!(database.info().source_os_build, Some(26200));

        let metadata = database
            .provider("Test-Provider")
            .expect("query")
            .expect("provider present");
        assert_eq!(metadata.events.len(), 1);
        assert_eq!(metadata.events[0].id, 2);
        assert_eq!(metadata.task_name(1), Some("Enrollment"));
        assert_eq!(metadata.opcode_name(11), Some("Start"));
        assert_eq!(metadata.keyword_names(1), vec!["Error"]);
        assert!(
            metadata.levels.is_empty(),
            "canonical DBs have no fabricated levels"
        );
    }

    #[test]
    fn provider_lookup_is_case_insensitive_like_the_column_and_the_event_log() {
        let dir = temp_dir("case");
        let path = dir.join("base.db");
        build_db(&path, &[("Test-Provider", 26200, EVENTS)]);

        let database = ProviderDb::open(&path).expect("opens");
        assert!(database.provider("test-PROVIDER").expect("query").is_some());
    }

    #[test]
    fn an_unknown_provider_is_absent_rather_than_an_error() {
        let dir = temp_dir("absent");
        let path = dir.join("base.db");
        build_db(&path, &[("Test-Provider", 26200, EVENTS)]);

        let database = ProviderDb::open(&path).expect("opens");
        assert!(database.provider("Nobody").expect("query").is_none());
    }

    #[test]
    fn the_newest_capture_wins_when_a_provider_appears_more_than_once() {
        let dir = temp_dir("versions");
        let path = dir.join("base.db");
        build_db(
            &path,
            &[
                (
                    "Dup",
                    22000,
                    r#"[{"Id":1,"Version":0,"Description":"old"}]"#,
                ),
                (
                    "Dup",
                    26200,
                    r#"[{"Id":1,"Version":0,"Description":"new"}]"#,
                ),
            ],
        );

        let metadata = ProviderDb::open(&path)
            .expect("opens")
            .provider("Dup")
            .expect("query")
            .expect("present");
        assert_eq!(
            metadata.events[0].description.as_deref(),
            Some("new"),
            "the newest captured build should win"
        );
    }
    #[test]
    fn provider_store_sorts_newest_builds_across_database_files() {
        let dir = temp_dir("cross-file-versions");
        // Directory order is intentionally opposite to build order. Appending files would select
        // the lower build from a-old.db; global ordering must select the higher build in z-new.db.
        build_db(
            &dir.join("a-old-name-low-build.db"),
            &[(
                "Cross-File",
                22000,
                r#"[{"Id":1,"Version":0,"Description":"oldest"}]"#,
            )],
        );
        build_db(
            &dir.join("z-new-name-high-build.db"),
            &[(
                "Cross-File",
                26200,
                r#"[{"Id":1,"Version":0,"Description":"newest"}]"#,
            )],
        );

        let mut store = ProviderStore::default();
        store.load_directory(&dir).expect("loads");
        let metadata = store
            .provider("Cross-File")
            .expect("query")
            .expect("provider present");
        assert_eq!(metadata.events[0].description.as_deref(), Some("newest"));
    }

    #[test]
    fn same_build_versions_use_a_deterministic_version_key_tie_break() {
        let dir = temp_dir("same-build-versions");
        let path = dir.join("base.db");
        build_db(
            &path,
            &[
                (
                    "Dup",
                    26200,
                    r#"[{"Id":1,"Version":0,"Description":"first"}]"#,
                ),
                (
                    "Dup",
                    26200,
                    r#"[{"Id":1,"Version":0,"Description":"second"}]"#,
                ),
            ],
        );
        let metadata = ProviderDb::open(&path)
            .expect("opens")
            .provider("Dup")
            .expect("query")
            .expect("present");
        assert_eq!(metadata.events[0].description.as_deref(), Some("first"));
    }
    #[test]
    fn a_merged_database_reports_no_single_source_build() {
        let dir = temp_dir("merged");
        let path = dir.join("base.db");
        build_db(&path, &[("A", 22000, EVENTS), ("B", 26200, EVENTS)]);

        // Reporting one of several builds would misrepresent where the metadata came from.
        assert_eq!(
            ProviderDb::open(&path)
                .expect("opens")
                .info()
                .source_os_build,
            None
        );
    }

    #[test]
    fn a_file_that_is_not_a_provider_database_is_rejected_clearly() {
        let dir = temp_dir("notadb");
        let path = dir.join("junk.db");
        std::fs::write(&path, b"this is not sqlite").expect("write");

        let error = ProviderDb::open(&path).expect_err("should fail");
        assert!(
            error.contains("does not look like a provider database"),
            "{error}"
        );
    }
    #[test]
    fn reads_eventlogexpert_value_map_definition_levels() {
        let blob = gzip_json(&serde_json::json!({
            "ValueMapDefinition": [{
                "Name": "levels",
                "Values": {
                    "2": "Information",
                    "4": "Warning"
                }
            }]
        }))
        .expect("compress map");

        assert_eq!(
            levels_from_maps(&blob).expect("read map"),
            BTreeMap::from([
                ("2".to_string(), "Information".to_string()),
                ("4".to_string(), "Warning".to_string())
            ])
        );
    }
    #[test]
    fn duplicate_level_values_keep_the_first_canonical_entry() {
        let blob = gzip_json(&serde_json::json!({
            "levels": {
                "Entries": [
                    {"Value": 2, "Name": "Information"},
                    {"Value": 2, "Name": "Informational"}
                ]
            }
        }))
        .expect("compress map");

        assert_eq!(
            levels_from_maps(&blob)
                .expect("read map")
                .get("2")
                .map(String::as_str),
            Some("Information")
        );
    }

    #[test]
    fn non_numeric_level_values_are_rejected() {
        let blob = gzip_json(&serde_json::json!({
            "levels": {
                "Entries": [{"Value": "not-a-number", "Name": "Invalid"}]
            }
        }))
        .expect("compress map");

        let error = levels_from_maps(&blob).expect_err("invalid level should fail");
        assert!(error.contains("UInt32"), "{error}");
    }

    #[test]
    fn an_empty_payload_is_an_empty_section_not_a_fault() {
        let empty: Vec<u8> = Vec::new();
        let events: Vec<cmtraceopen_parser::provider::ProviderEvent> =
            inflate_json(&empty).expect("empty blob is fine");
        assert!(events.is_empty());
    }

    #[test]
    fn a_corrupt_payload_is_reported_rather_than_silently_empty() {
        let result: Result<Vec<cmtraceopen_parser::provider::ProviderEvent>, String> =
            inflate_json(b"not gzip at all");
        assert!(result.is_err(), "corrupt payloads must not read as empty");
    }

    #[test]
    fn loading_a_directory_registers_every_database_and_skips_other_files() {
        let dir = temp_dir("directory");
        build_db(&dir.join("a.db"), &[("A", 26200, EVENTS)]);
        build_db(&dir.join("b.db"), &[("B", 26200, EVENTS)]);
        std::fs::write(dir.join("notes.txt"), b"ignore me").expect("write");
        std::fs::write(dir.join("bad.db"), b"not a provider database").expect("write");

        // A store local to this test. The old process global meant a parallel test registering a
        // different directory replaced this one's set mid-run.
        let mut store = ProviderStore::default();
        let outcome = store.load_directory(&dir).expect("loads");
        assert_eq!(outcome.loaded.len(), 2);
        assert_eq!(outcome.failures.len(), 1);
        assert!(outcome.failures[0].path.ends_with("bad.db"));
        assert!(store.provider("A").expect("query").is_some());
        assert!(store.provider("B").expect("query").is_some());
        assert!(store.provider("Nobody").expect("query").is_none());
        assert_eq!(store.registered().len(), 2);
    }
    #[test]
    fn packaged_provider_load_requires_complete_coverage() {
        let loaded = ProviderDbLoadOutcome {
            loaded: vec![ProviderDbInfo {
                path: "valid.db".into(),
                provider_count: 1,
                source_os_build: Some(26200),
            }],
            failures: vec![ProviderDbLoadFailure {
                path: "broken.db".into(),
                reason: "invalid schema".into(),
            }],
        };
        assert!(!super::packaged_provider_load_is_complete(&loaded));
        assert!(super::packaged_provider_load_is_complete(
            &ProviderDbLoadOutcome {
                failures: Vec::new(),
                ..loaded
            }
        ));
    }

    #[test]
    fn a_written_database_round_trips_through_the_reader() {
        use cmtraceopen_parser::provider::{ProviderEvent, ProviderMessage};

        let dir = temp_dir("roundtrip");
        let path = dir.join("capture.db");

        let metadata = ProviderMetadata {
            provider_name: "Round-Trip-Provider".to_string(),
            events: vec![ProviderEvent {
                id: 2,
                version: 0,
                description: Some("Enroll failed: (%1).".to_string()),
                log_name: Some(
                    "Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider/Admin"
                        .to_string(),
                ),
                level: Some(2),
                task: Some(1),
                opcode: Some(11),
                keywords: vec![0x8000_0000_0000_0000],
                template: None,
            }],
            messages: vec![ProviderMessage {
                raw_id: 0x8000_0002,
                short_id: 2,
                provider_name: Some("Round-Trip-Provider".to_string()),
                template: Some("<template />".to_string()),
                tag: Some("Enrollment".to_string()),
                log_link: Some("https://example.invalid/event/2".to_string()),
                text: Some("Enroll failed: (%1).".to_string()),
            }],
            levels: [("2".to_string(), "Information".to_string())]
                .into_iter()
                .collect(),
            tasks: [("1".to_string(), "Enrollment".to_string())]
                .into_iter()
                .collect(),
            keywords: [("1".to_string(), "Error".to_string())]
                .into_iter()
                .collect(),
            unavailable_categories: ["keywords".to_string()].into_iter().collect(),
            opcodes: [("11".to_string(), "Start".to_string())]
                .into_iter()
                .collect(),
            source_os_build: Some(26200),
        };

        let captured = CapturedProviderMetadata {
            metadata: metadata.clone(),
            version_key: "publisher-version-key".to_string(),
        };

        let mut older_metadata = metadata.clone();
        older_metadata.source_os_build = Some(26100);
        let older = CapturedProviderMetadata {
            metadata: older_metadata,
            version_key: "publisher-version-key-old".to_string(),
        };

        let written = write_provider_database(&path, &[captured.clone(), older]).expect("write");
        assert_eq!(written, 2);
        let database = ProviderDb::open(&path).expect("opens");
        assert!(database.has_capture_state);
        let read = database
            .provider("Round-Trip-Provider")
            .expect("query")
            .expect("present");
        assert_eq!(read, metadata);
        assert_eq!(
            read.unavailable_categories,
            ["keywords".to_string()].into_iter().collect()
        );
        assert_eq!(
            read.levels.get("2").map(String::as_str),
            Some("Information")
        );
        assert!(read.unavailable_categories.contains("keywords"));
        let rows = database.rows().expect("all captured rows");
        assert_eq!(rows.len(), 2);
        assert_eq!(
            rows.iter()
                .map(|row| row.version_key.as_str())
                .collect::<Vec<_>>(),
            vec!["publisher-version-key", "publisher-version-key-old"]
        );
        assert_eq!(
            rows.iter()
                .map(|row| row.metadata.source_os_build)
                .collect::<Vec<_>>(),
            vec![Some(26200), Some(26100)]
        );
        assert!(rows
            .iter()
            .all(|row| row.metadata.unavailable_categories.contains("keywords")));
        let version_key: String = database
            .connection
            .query_row(
                "SELECT VersionKey FROM ProviderDetails WHERE ProviderName = ?1 \
                 ORDER BY SourceOsBuild DESC LIMIT 1",
                ["Round-Trip-Provider"],
                |row| row.get(0),
            )
            .expect("version key");
        assert_eq!(version_key, "publisher-version-key");
        let maps_blob: Vec<u8> = database
            .connection
            .query_row(
                "SELECT Maps FROM ProviderDetails WHERE ProviderName = ?1 AND VersionKey = ?2",
                rusqlite::params!["Round-Trip-Provider", "publisher-version-key"],
                |row| row.get(0),
            )
            .expect("maps blob");
        let maps: serde_json::Value = inflate_json(&maps_blob).expect("maps JSON");
        assert_eq!(
            maps,
            serde_json::json!({
                "levels": {
                    "Entries": [{"Value": 2, "Name": "Information"}],
                    "IsBitMap": false
                }
            })
        );
        for column in [
            "ResolvedFromOwningPublisher",
            "SourceOsRevision",
            "SourceOsEdition",
            "SourceOsDisplayVersion",
            "MessageFileVersion",
        ] {
            let present: i64 = database
                .connection
                .query_row(
                    "SELECT COUNT(*) FROM pragma_table_info('ProviderDetails') WHERE name = ?1",
                    [column],
                    |row| row.get(0),
                )
                .expect("canonical nullable column query");
            assert_eq!(present, 1, "missing canonical column {column}");
        }
    }
    #[test]
    fn failed_replacement_does_not_wipe_previous_database() {
        let dir = temp_dir("atomic");
        let path = dir.join("base.db");
        let metadata = ProviderMetadata {
            provider_name: "Atomic".to_string(),
            ..ProviderMetadata::default()
        };
        let captured = CapturedProviderMetadata {
            metadata,
            version_key: "version".to_string(),
        };
        write_provider_database(&path, std::slice::from_ref(&captured)).expect("initial write");
        assert!(write_provider_database(&path, &[captured.clone(), captured]).is_err());
        assert!(ProviderDb::open(&path)
            .expect("database remains readable")
            .provider("Atomic")
            .expect("provider query")
            .is_some());
    }
    #[test]
    fn reading_rows_preserves_every_provider_version_and_description() {
        let dir = temp_dir("all-rows");
        let path = dir.join("capture.db");
        build_db(
            &path,
            &[
                (
                    "Multi-Version",
                    26100,
                    r#"[{"Id":7,"Version":0,"Description":"old %1"}]"#,
                ),
                (
                    "Multi-Version",
                    26200,
                    r#"[{"Id":7,"Version":1,"Description":"new %1"}]"#,
                ),
            ],
        );
        let database = ProviderDb::open(&path).expect("opens");

        let rows = database.rows().expect("reads all rows");
        assert_eq!(rows[0].version_key, "vk1:26200:1");
        assert_eq!(rows[1].version_key, "vk1:26100:0");
        assert_eq!(
            rows[0].metadata.events[0].description.as_deref(),
            Some("new %1")
        );
        assert_eq!(
            rows[1].metadata.events[0].description.as_deref(),
            Some("old %1")
        );
    }

    #[test]
    fn nullable_external_version_and_payload_columns_still_yield_a_row() {
        let dir = temp_dir("nullable-import");
        let path = dir.join("capture.db");
        let connection = Connection::open(&path).expect("create");
        connection
            .execute_batch(
                r#"CREATE TABLE ProviderDetails (
                    ProviderName TEXT COLLATE NOCASE,
                    VersionKey TEXT,
                    Events BLOB, Keywords BLOB, Maps BLOB, Messages BLOB,
                    Opcodes BLOB, Parameters BLOB, Tasks BLOB, SourceOsBuild INTEGER
                );"#,
            )
            .expect("schema");
        connection
            .execute(
                "INSERT INTO ProviderDetails (ProviderName) VALUES ('Nullable')",
                [],
            )
            .expect("nullable row");
        drop(connection);

        let database = ProviderDb::open(&path).expect("opens");
        assert!(!database.has_capture_state);
        let rows = database
            .rows()
            .expect("nullable fields are valid imported data");
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].version_key, "");
        assert_eq!(rows[0].metadata.provider_name, "Nullable");
        assert!(rows[0].metadata.events.is_empty());
        assert!(rows[0].metadata.messages.is_empty());
    }

    #[test]
    fn malformed_source_build_schema_is_rejected_precisely() {
        let dir = temp_dir("malformed-schema");
        let path = dir.join("capture.db");
        let connection = Connection::open(&path).expect("create");
        connection
            .execute_batch("CREATE TABLE ProviderDetails (ProviderName TEXT, VersionKey TEXT);")
            .expect("schema");

        let error = ProviderDb::open(&path).expect_err("missing source build column");
        assert!(error.contains("SourceOsBuild"), "{error}");
        assert!(error.contains("provider database"), "{error}");
    }

    #[test]
    fn replacement_updates_an_existing_destination_in_place() {
        let dir = temp_dir("replacement");
        let path = dir.join("capture.db");
        let old = ProviderMetadata {
            provider_name: "Old".to_string(),
            ..ProviderMetadata::default()
        };
        write_provider_database(
            &path,
            &[CapturedProviderMetadata {
                metadata: old,
                version_key: "old".to_string(),
            }],
        )
        .expect("initial write");

        let replacement = ProviderMetadata {
            provider_name: "New".to_string(),
            ..ProviderMetadata::default()
        };
        write_provider_database(
            &path,
            &[CapturedProviderMetadata {
                metadata: replacement,
                version_key: "new".to_string(),
            }],
        )
        .expect("replacement write");

        let database = ProviderDb::open(&path).expect("replacement opens");
        assert!(database.provider("Old").expect("old query").is_none());
        assert!(database.provider("New").expect("new query").is_some());
    }

    #[test]
    fn provider_lookup_selects_exact_event_version_across_all_provider_rows() {
        let dir = temp_dir("event-version-lookup");
        let path = dir.join("capture.db");
        build_db(
            &path,
            &[
                (
                    "Multi-Version",
                    26200,
                    r#"[{"Id":7,"Version":0,"Description":"old-row"}]"#,
                ),
                (
                    "Multi-Version",
                    26200,
                    r#"[{"Id":8,"Version":0,"Description":"highest-row"}]"#,
                ),
            ],
        );
        let mut store = ProviderStore::default();
        store.load_directory(&dir).expect("loads");

        let metadata = store
            .provider_for_event("Multi-Version", "Some-Channel", 7, Some(0))
            .expect("lookup succeeds")
            .expect("matching event exists");
        assert_eq!(
            metadata.events[0].description.as_deref(),
            Some("old-row"),
            "an exact event/version match must beat the highest provider row"
        );
    }

    #[test]
    fn provider_lookup_surfaces_corrupt_payload_errors() {
        let dir = temp_dir("corrupt-provider");
        let path = dir.join("capture.db");
        build_db(&path, &[("Broken", 26200, EVENTS)]);
        let connection = Connection::open(&path).expect("open");
        connection
            .execute(
                "UPDATE ProviderDetails SET Events = ?1 WHERE ProviderName = 'Broken'",
                [b"not gzip".as_slice()],
            )
            .expect("corrupt payload");
        drop(connection);

        let mut store = ProviderStore::default();
        store.load_directory(&dir).expect("database opens");
        let error = store
            .provider("Broken")
            .expect_err("corrupt provider payload must not become a normal miss");
        assert!(error.contains("not valid gzip"), "{error}");
    }

    #[test]
    fn generated_parameters_preserve_unavailable_category_coverage() {
        let dir = temp_dir("parameters-coverage");
        let path = dir.join("capture.db");
        let metadata = ProviderMetadata {
            provider_name: "Coverage".to_string(),
            unavailable_categories: ["keywords".to_string()].into_iter().collect(),
            ..ProviderMetadata::default()
        };
        write_provider_database(
            &path,
            &[CapturedProviderMetadata {
                metadata,
                version_key: "version".to_string(),
            }],
        )
        .expect("write");
        let database = ProviderDb::open(&path).expect("open");
        let parameters_blob: Vec<u8> = database
            .connection
            .query_row(
                "SELECT Parameters FROM ProviderDetails WHERE ProviderName = 'Coverage'",
                [],
                |row| row.get(0),
            )
            .expect("parameters");
        let parameters: serde_json::Value =
            inflate_json(&parameters_blob).expect("parameters JSON");
        assert_eq!(parameters, serde_json::json!([]));
        let unavailable: Vec<u8> = database
            .connection
            .query_row(
                "SELECT UnavailableCategories FROM ProviderCaptureState \
                 WHERE ProviderName = 'Coverage' AND VersionKey = 'version'",
                [],
                |row| row.get(0),
            )
            .expect("capture state");
        assert_eq!(
            inflate_json::<BTreeSet<String>>(&unavailable).expect("coverage JSON"),
            ["keywords".to_string()].into_iter().collect()
        );
    }

    #[test]
    fn exporting_a_database_preserves_the_canonical_rows() {
        let dir = temp_dir("export");
        let source = dir.join("source.db");
        let destination = dir.join("destination.db");
        build_db(
            &source,
            &[
                ("A", 26100, r#"[{"Id":1,"Version":0,"Description":"a"}]"#),
                ("A", 26200, r#"[{"Id":1,"Version":1,"Description":"b"}]"#),
            ],
        );
        let source_connection = Connection::open(&source).expect("open source");
        source_connection
            .execute_batch(
                r#"ALTER TABLE ProviderDetails ADD COLUMN MessageFileVersion TEXT;
                   UPDATE ProviderDetails SET MessageFileVersion = '10.0.26200.1';"#,
            )
            .expect("canonical nullable column");
        drop(source_connection);

        let info = export_provider_database(&source, &destination).expect("exports");
        assert_eq!(info.provider_count, 2);
        let exported = ProviderDb::open(&destination).expect("opens export");
        let rows = exported.rows().expect("reads export rows");
        assert_eq!(
            rows.iter()
                .map(|row| row.version_key.as_str())
                .collect::<Vec<_>>(),
            vec!["vk1:26200:1", "vk1:26100:0"]
        );
        let message_file_version: String = exported
            .connection
            .query_row(
                "SELECT MessageFileVersion FROM ProviderDetails WHERE ProviderName = 'A' LIMIT 1",
                [],
                |row| row.get(0),
            )
            .expect("canonical nullable value");
        assert_eq!(message_file_version, "10.0.26200.1");
        assert_eq!(
            rows.iter()
                .map(|row| row.metadata.events[0].description.as_deref())
                .collect::<Vec<_>>(),
            vec![Some("b"), Some("a")]
        );
    }

    #[test]
    fn packaged_validation_accepts_multiple_versions_for_one_provider() {
        let root = temp_dir("packaged-multiple-versions");
        let directory = root.join(PACKAGED_PROVIDER_DATABASE_DIRECTORY);
        std::fs::create_dir_all(&directory).expect("provider package directory");
        let path = directory.join("multiple-versions.db");
        build_db(
            &path,
            &[
                ("Repeated-Provider", 20348, EVENTS),
                ("Repeated-Provider", 20348, EVENTS),
            ],
        );

        let entry = PackagedProviderDatabase {
            file: "multiple-versions.db".into(),
            source_windows_build: 20348,
            sha256: sha256_file(&path).expect("database hash"),
            provider_count: 2,
            providers: vec!["Repeated-Provider".into()],
        };

        validate_packaged_provider_database(&directory, &entry)
            .expect("row count and distinct provider names are independent");
    }

    #[test]
    fn packaged_discovery_reports_the_real_artifact_prerequisite() {
        let dir = temp_dir("packaged-missing");
        std::fs::create_dir_all(dir.join(PACKAGED_PROVIDER_DATABASE_DIRECTORY))
            .expect("provider resource directory");
        std::fs::write(
            dir.join(PACKAGED_PROVIDER_DATABASE_DIRECTORY)
                .join(PACKAGED_PROVIDER_MANIFEST_FILE),
            r#"{"schemaVersion":1,"status":"unavailable","reason":"Windows capture input is not available","providerFamilies":["MDM","Autopilot","ESP","AAD","ConfigMgr client","AppX","Windows Update"]}"#,
        )
        .expect("manifest");
        let error = packaged_provider_directory(&dir).expect_err("no packaged artifact");
        assert!(error.contains("status unavailable"), "{error}");
        assert!(
            error.contains("Windows capture input is not available"),
            "{error}"
        );
        assert!(error.contains("MDM"), "{error}");
        assert!(error.contains("ProviderDetails"), "{error}");
    }
    #[test]
    fn packaged_discovery_rejects_a_missing_declared_database() {
        let root = copy_checked_in_package("packaged-missing-declared");
        let directory = root.join(PACKAGED_PROVIDER_DATABASE_DIRECTORY);
        let missing = directory.join("cmtraceopen-provider-windows-20348.db");
        std::fs::remove_file(&missing).expect("remove declared database");

        let error = packaged_provider_directory(&root).expect_err("missing database must fail");

        assert!(error.contains("missing"), "{error}");
        assert!(
            error.contains("cmtraceopen-provider-windows-20348.db"),
            "{error}"
        );
    }

    #[test]
    fn packaged_discovery_rejects_an_undeclared_database() {
        let root = copy_checked_in_package("packaged-extra");
        let directory = root.join(PACKAGED_PROVIDER_DATABASE_DIRECTORY);
        std::fs::copy(
            directory.join("cmtraceopen-provider-windows-20348.db"),
            directory.join("unexpected.db"),
        )
        .expect("copy undeclared database");

        let error = packaged_provider_directory(&root).expect_err("extra database must fail");

        assert!(error.contains("undeclared"), "{error}");
        assert!(error.contains("unexpected.db"), "{error}");
    }

    #[test]
    fn packaged_discovery_rejects_a_database_hash_mismatch() {
        let root = copy_checked_in_package("packaged-hash-mismatch");
        let manifest_path = root
            .join(PACKAGED_PROVIDER_DATABASE_DIRECTORY)
            .join(PACKAGED_PROVIDER_MANIFEST_FILE);
        let manifest = std::fs::read_to_string(&manifest_path).expect("read manifest");
        let wrong_hash = "0".repeat(64);
        let tampered = manifest.replace(
            "5a49ab87cb81caba2cb37cfc364de4e22a9f95276c91661d528fcab2a2158849",
            &wrong_hash,
        );
        std::fs::write(&manifest_path, tampered).expect("tamper manifest hash");

        let error = packaged_provider_directory(&root).expect_err("hash mismatch must fail");

        assert!(error.contains("sha256"), "{error}");
        assert!(error.contains("20348.db"), "{error}");
    }

    #[test]
    fn packaged_discovery_rejects_provider_metadata_mismatch() {
        let root = copy_checked_in_package("packaged-metadata-mismatch");
        let manifest_path = root
            .join(PACKAGED_PROVIDER_DATABASE_DIRECTORY)
            .join(PACKAGED_PROVIDER_MANIFEST_FILE);
        let manifest = std::fs::read_to_string(&manifest_path).expect("read manifest");
        let tampered = manifest.replace("\"providerCount\": 1", "\"providerCount\": 2");
        std::fs::write(&manifest_path, tampered).expect("tamper provider count");

        let error =
            packaged_provider_directory(&root).expect_err("provider metadata mismatch must fail");

        assert!(error.contains("providerCount"), "{error}");
        assert!(error.contains("20348.db"), "{error}");
    }

    #[test]
    fn packaged_discovery_rejects_a_source_build_mismatch() {
        let root = copy_checked_in_package("packaged-source-mismatch");
        let manifest_path = root
            .join(PACKAGED_PROVIDER_DATABASE_DIRECTORY)
            .join(PACKAGED_PROVIDER_MANIFEST_FILE);
        let manifest = std::fs::read_to_string(&manifest_path).expect("read manifest");
        let tampered = manifest.replace(
            "\"sourceWindowsBuild\": 20348",
            "\"sourceWindowsBuild\": 20347",
        );
        std::fs::write(&manifest_path, tampered).expect("tamper source build");

        let error = packaged_provider_directory(&root).expect_err("source build must fail");

        assert!(error.contains("sourceWindowsBuild"), "{error}");
        assert!(error.contains("20347"), "{error}");
    }

    #[test]
    fn packaged_discovery_rejects_provider_name_mismatch() {
        let root = copy_checked_in_package("packaged-provider-name-mismatch");
        let manifest_path = root
            .join(PACKAGED_PROVIDER_DATABASE_DIRECTORY)
            .join(PACKAGED_PROVIDER_MANIFEST_FILE);
        let manifest = std::fs::read_to_string(&manifest_path).expect("read manifest");
        let tampered = manifest.replace("Microsoft-ConfigMgr", "Wrong-Provider");
        std::fs::write(&manifest_path, tampered).expect("tamper provider name");

        let error = packaged_provider_directory(&root).expect_err("provider name must fail");

        assert!(error.contains("providers do not match"), "{error}");
        assert!(error.contains("20348.db"), "{error}");
    }

    #[test]
    fn checked_in_packaged_manifest_loads_curated_provenance() {
        let resource_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("resources");
        let directory =
            packaged_provider_directory(&resource_dir).expect("curated provider artifact");
        let mut store = ProviderStore::default();
        let outcome = store
            .load_directory(&directory)
            .expect("load curated providers");
        assert_eq!(outcome.failures, Vec::new());
        assert_eq!(outcome.loaded.len(), 2);
        assert_eq!(
            outcome
                .loaded
                .iter()
                .filter_map(|info| info.source_os_build)
                .collect::<BTreeSet<_>>(),
            [20348, 26200].into_iter().collect()
        );

        for provider in [
            "Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider",
            "Microsoft-Windows-ModernDeployment-Diagnostics-Provider",
            "Microsoft-Windows-Provisioning-Diagnostics-Provider",
            "Microsoft-Windows-AAD",
            "Microsoft-ConfigMgr",
            "Microsoft-Windows-AppXDeployment-Server",
            "Microsoft-Windows-WindowsUpdateClient",
        ] {
            let metadata = store
                .provider(provider)
                .expect("provider lookup")
                .expect("curated provider is present");
            assert!(
                !metadata.events.is_empty(),
                "{provider} must retain event metadata"
            );
        }
    }

    #[test]
    fn tauri_package_maps_provider_resources_to_the_runtime_lookup_directory() {
        let config: serde_json::Value = serde_json::from_str(include_str!("../../tauri.conf.json"))
            .expect("tauri.conf.json must parse");
        let source = format!("resources/{PACKAGED_PROVIDER_DATABASE_DIRECTORY}");
        let destination = config
            .pointer("/bundle/resources")
            .and_then(serde_json::Value::as_object)
            .and_then(|resources| resources.get(&source))
            .and_then(serde_json::Value::as_str);

        assert_eq!(
            destination,
            Some(PACKAGED_PROVIDER_DATABASE_DIRECTORY),
            "the packaged destination must match packaged_provider_directory(resource_dir)"
        );
    }
}

#[cfg(test)]
mod real_database_tests {
    //! Exercises the reader against a provider database produced by EventLogExpert's own tool.
    //!
    //! Ignored by default: it needs a real `.db`, whose path comes from
    //! `CMTRACEOPEN_PROVIDER_DB`. Synthetic fixtures prove the reader handles the schema as I
    //! understand it; only a real file proves I understood it.
    //!
    //! ```text
    //! CMTRACEOPEN_PROVIDER_DB=C:\path\to.db \
    //!   cargo test --lib event_log::provider_db::real_database_tests -- --ignored --nocapture
    //! ```

    use super::*;

    fn real_db() -> Option<ProviderDb> {
        let path = std::env::var("CMTRACEOPEN_PROVIDER_DB").ok()?;
        ProviderDb::open(Path::new(&path)).ok()
    }

    #[test]
    #[ignore = "requires a real provider database via CMTRACEOPEN_PROVIDER_DB"]
    fn opens_a_real_database_and_reports_its_size() {
        let database = real_db().expect("database opens");
        let info = database.info();
        println!(
            "providers={} source_os_build={:?}",
            info.provider_count, info.source_os_build
        );
        assert!(
            info.provider_count > 100,
            "a machine-wide capture should hold hundreds of providers, got {}",
            info.provider_count
        );
    }

    #[test]
    #[ignore = "requires a real provider database via CMTRACEOPEN_PROVIDER_DB"]
    fn renders_a_real_mdm_description_end_to_end() {
        use cmtraceopen_parser::provider::render_description;

        let database = real_db().expect("database opens");
        let metadata = database
            .provider("Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider")
            .expect("query succeeds")
            .expect("the MDM provider is present on a Windows machine");

        println!(
            "MDM provider: {} events, {} tasks, {} keywords",
            metadata.events.len(),
            metadata.tasks.len(),
            metadata.keywords.len()
        );
        assert!(
            metadata.events.len() > 50,
            "the MDM provider defines many events, got {}",
            metadata.events.len()
        );

        let channel = metadata
            .events
            .iter()
            .find(|event| event.id == 4 && event.version == 0)
            .and_then(|event| event.log_name.as_deref())
            .expect("event 4 has a captured channel")
            .to_string();
        let event = metadata
            .event(4, Some(0), Some(&channel))
            .expect("event id 4 is defined");
        let template = event
            .description
            .as_deref()
            .expect("event 4 has a description");
        println!("template: {template}");

        let rendered = render_description(template, &[]);
        println!("rendered: {}", rendered.text);
        assert!(!rendered.text.is_empty());
        assert!(rendered.is_complete());
    }

    #[test]
    #[ignore = "requires a real provider database via CMTRACEOPEN_PROVIDER_DB"]
    fn every_payload_in_a_sample_of_providers_inflates() {
        // A decompression or schema misunderstanding would show up here rather than as one
        // provider quietly rendering nothing.
        let database = real_db().expect("database opens");
        let names: Vec<String> = {
            let mut statement = database
                .connection
                .prepare("SELECT ProviderName FROM ProviderDetails LIMIT 200")
                .expect("prepare");
            let rows = statement
                .query_map([], |row| row.get::<_, String>(0))
                .expect("query");
            rows.filter_map(Result::ok).collect()
        };
        assert!(!names.is_empty());

        let mut with_events = 0usize;
        for name in &names {
            let metadata = database
                .provider(name)
                .unwrap_or_else(|error| panic!("provider {name} failed to inflate: {error}"))
                .unwrap_or_else(|| panic!("provider {name} vanished between listing and reading"));
            if !metadata.events.is_empty() {
                with_events += 1;
            }
        }
        println!(
            "{}/{} sampled providers define events",
            with_events,
            names.len()
        );
        assert!(with_events > 0);
    }
}
