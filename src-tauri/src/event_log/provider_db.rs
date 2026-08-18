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
//!   "SourceOsBuild" INTEGER, "SourceOsEdition" TEXT, ...
//!   PRIMARY KEY ("ProviderName","VersionKey"))
//! ```
//!
//! Every BLOB is gzip-compressed JSON. A real database holds about 1,180 providers in 16 MB, so
//! rows are read on demand and cached rather than loaded eagerly.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use cmtraceopen_parser::provider::ProviderMetadata;
use flate2::read::GzDecoder;
use flate2::write::GzEncoder;
use flate2::Compression;
use rusqlite::{Connection, OpenFlags};
use serde::{Deserialize, Serialize};

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

/// Decompresses one gzip JSON payload into `T`.
///
/// An empty BLOB is a legitimately empty section rather than a fault, so it deserializes to the
/// type's default instead of erroring.
/// Largest decompressed provider payload accepted from a database.
///
/// The biggest real provider in a 15.8 MB capture inflates to well under a megabyte, so 64 MB
/// refuses only what could not be a genuine payload.
const MAX_PROVIDER_PAYLOAD_BYTES: u64 = 64 * 1024 * 1024;

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

        // Only meaningful when the whole database came from one capture, which is the normal case;
        // a merged database reports nothing rather than an arbitrary one of several builds. One
        // query answers both halves: MIN and MAX agree exactly when there is a single build.
        let source_os_build: Option<u32> = connection
            .query_row(
                "SELECT MIN(SourceOsBuild), MAX(SourceOsBuild) FROM ProviderDetails",
                [],
                |row| Ok((row.get::<_, Option<u32>>(0)?, row.get::<_, Option<u32>>(1)?)),
            )
            .ok()
            .and_then(|(low, high)| match (low, high) {
                (Some(low), Some(high)) if low == high => Some(low),
                _ => None,
            });

        Ok(Self {
            info: ProviderDbInfo {
                path: path.display().to_string(),
                provider_count: provider_count.max(0) as u64,
                source_os_build,
            },
            connection,
        })
    }

    /// Summary of what this database holds.
    pub fn info(&self) -> &ProviderDbInfo {
        &self.info
    }

    /// Loads one provider's metadata.
    ///
    /// Provider names are compared case-insensitively, matching the column's `COLLATE NOCASE` and
    /// how the event log itself treats them. When several rows exist for one provider, because a
    /// database merged captures from different builds, the highest `SourceOsBuild` wins as the
    /// closest match to a modern machine.
    pub fn provider(&self, name: &str) -> Result<Option<ProviderMetadata>, String> {
        let mut statement = self
            .connection
            .prepare_cached(
                "SELECT Events, Messages, Tasks, Keywords, Opcodes, SourceOsBuild \
                 FROM ProviderDetails WHERE ProviderName = ?1 \
                 ORDER BY SourceOsBuild DESC LIMIT 1",
            )
            .map_err(|error| format!("cannot prepare provider query: {error}"))?;

        let row = statement.query_row([name], |row| {
            Ok((
                row.get::<_, Vec<u8>>(0)?,
                row.get::<_, Vec<u8>>(1)?,
                row.get::<_, Vec<u8>>(2)?,
                row.get::<_, Vec<u8>>(3)?,
                row.get::<_, Vec<u8>>(4)?,
                row.get::<_, Option<u32>>(5)?,
            ))
        });

        let (events, messages, tasks, keywords, opcodes, build) = match row {
            Ok(values) => values,
            Err(rusqlite::Error::QueryReturnedNoRows) => return Ok(None),
            Err(error) => return Err(format!("cannot read provider {name}: {error}")),
        };

        Ok(Some(ProviderMetadata {
            provider_name: name.to_string(),
            events: inflate_json(&events)?,
            messages: inflate_json(&messages)?,
            tasks: inflate_json(&tasks)?,
            keywords: inflate_json(&keywords)?,
            opcodes: inflate_json(&opcodes)?,
            source_os_build: build,
        }))
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
    PRIMARY KEY ("ProviderName","VersionKey"));"#;

/// Serializes `value` to JSON and gzip-compresses it, the way EventLogExpert stores each section.
fn gzip_json<T: Serialize>(value: &T) -> Result<Vec<u8>, String> {
    let json = serde_json::to_vec(value)
        .map_err(|error| format!("cannot serialize provider metadata: {error}"))?;
    let mut encoder = GzEncoder::new(Vec::new(), Compression::fast());
    encoder
        .write_all(&json)
        .map_err(|error| format!("cannot compress provider metadata: {error}"))?;
    encoder
        .finish()
        .map_err(|error| format!("cannot finish compressing provider metadata: {error}"))
}

/// Writes captured provider metadata to a new database in EventLogExpert's schema.
///
/// This is the write side of the capture pipeline (issue #539): the Windows capture walk builds
/// [`ProviderMetadata`] values and hands them here, and [`ProviderDb::open`] reads the result back.
/// The round-trip through those two is how a curated database ships. `Maps` and `Parameters` are
/// written empty because neither the reader nor the capture model consumes them.
pub fn write_provider_database(
    path: &Path,
    providers: &[ProviderMetadata],
) -> Result<usize, String> {
    let connection = Connection::open(path).map_err(|error| {
        format!(
            "cannot create provider database {}: {error}",
            path.display()
        )
    })?;
    connection
        .execute_batch(PROVIDER_DETAILS_SCHEMA)
        .map_err(|error| format!("cannot create provider database schema: {error}"))?;
    // Writing a database is a full replacement, not an append: a stale provider row from an earlier
    // capture at the same path must not survive into the new set.
    connection
        .execute("DELETE FROM ProviderDetails", [])
        .map_err(|error| format!("cannot clear provider database: {error}"))?;

    let empty_object = serde_json::json!({});
    let empty_array = serde_json::json!([]);

    for metadata in providers {
        let build = metadata.source_os_build.unwrap_or(0);
        let events = gzip_json(&metadata.events)?;
        let keywords = gzip_json(&metadata.keywords)?;
        let maps = gzip_json(&empty_object)?;
        let messages = gzip_json(&metadata.messages)?;
        let opcodes = gzip_json(&metadata.opcodes)?;
        let parameters = gzip_json(&empty_array)?;
        let tasks = gzip_json(&metadata.tasks)?;

        connection
            .execute(
                r#"INSERT INTO ProviderDetails
                   (ProviderName, VersionKey, Events, Keywords, Maps, Messages, Opcodes,
                    Parameters, Tasks, SourceOsBuild)
                   VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)"#,
                rusqlite::params![
                    metadata.provider_name,
                    format!("vk1:{build}"),
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
                    "cannot insert provider {}: {error}",
                    metadata.provider_name
                )
            })?;
    }
    Ok(providers.len())
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
    /// The registered databases, opened once at registration and reused for every lookup.
    open_databases: Mutex<Vec<ProviderDb>>,
    info: Vec<ProviderDbInfo>,
}

impl ProviderStore {
    /// Registers every `.db` in `directory`, replacing any previously registered set.
    pub fn load_directory(&mut self, directory: &Path) -> Result<Vec<ProviderDbInfo>, String> {
        let entries = std::fs::read_dir(directory).map_err(|error| {
            format!(
                "cannot read provider database directory {}: {error}",
                directory.display()
            )
        })?;

        let mut databases: Vec<ProviderDb> = Vec::new();
        let mut info = Vec::new();
        let mut failures: Vec<String> = Vec::new();

        let mut paths: Vec<PathBuf> = Vec::new();
        for entry in entries {
            // An enumeration error after the directory opened is recorded, not skipped, matching
            // the map loader. Dropping it lets a partial set look complete.
            match entry {
                Ok(entry) => paths.push(entry.path()),
                Err(error) => failures.push(format!(
                    "cannot read an entry in {}: {error}",
                    directory.display()
                )),
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
                Err(reason) => failures.push(reason),
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
        *open = databases;
        cache.clear();
        drop(open);
        drop(cache);
        self.info = info.clone();

        if info.is_empty() && !failures.is_empty() {
            return Err(failures.join("; "));
        }
        // Reported even when something loaded. Returning Ok and dropping four reasons on the floor
        // leaves an operator looking at partial provider coverage with no explanation for it.
        for failure in &failures {
            log::warn!(
                "event=provider_db_skipped directory=\"{}\" reason=\"{failure}\"",
                directory.display()
            );
        }
        Ok(info)
    }

    /// Metadata for `provider_name`, consulting registered databases in order and caching it.
    ///
    /// The cache is behind its own lock, so this needs only `&self`; a lookup still populates it,
    /// including the negative result, which is what stops a provider absent from every database
    /// being searched again for every event that names it.
    pub fn provider(&self, provider_name: &str) -> Option<Arc<ProviderMetadata>> {
        let key = provider_name.to_ascii_lowercase();
        if let Ok(cache) = self.cache.lock() {
            if let Some(cached) = cache.get(&key) {
                return cached.clone();
            }
        }

        // Databases are opened once and held, not reopened per lookup. Opening also runs a schema
        // probe, so a miss used to pay an open plus that probe for every registered database, for
        // every distinct provider name in the file.
        let mut found = None;
        if let Ok(open) = self.open_databases.lock() {
            for database in open.iter() {
                if let Ok(Some(metadata)) = database.provider(provider_name) {
                    found = Some(metadata);
                    break;
                }
            }
        }

        let found = found.map(Arc::new);
        if let Ok(mut cache) = self.cache.lock() {
            cache.insert(key, found.clone());
        }
        found
    }

    /// Summary of every registered database.
    pub fn registered(&self) -> Vec<ProviderDbInfo> {
        self.info.clone()
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

        for (name, build, events_json) in providers {
            connection
                .execute(
                    r#"INSERT INTO ProviderDetails
                       (ProviderName, VersionKey, Events, Keywords, Maps, Messages, Opcodes,
                        Parameters, Tasks, SourceOsBuild)
                       VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)"#,
                    rusqlite::params![
                        name,
                        format!("vk1:{build}"),
                        gzip(events_json),
                        gzip(r#"{"1":"Error"}"#),
                        gzip("{}"),
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

        // A store local to this test. The old process global meant a parallel test registering a
        // different directory replaced this one's set mid-run.
        let mut store = ProviderStore::default();
        let info = store.load_directory(&dir).expect("loads");
        assert_eq!(info.len(), 2);
        assert!(store.provider("A").is_some());
        assert!(store.provider("B").is_some());
        assert!(store.provider("Nobody").is_none());
        assert_eq!(store.registered().len(), 2);
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
                text: Some("Enroll failed: (%1).".to_string()),
            }],
            tasks: [("1".to_string(), "Enrollment".to_string())]
                .into_iter()
                .collect(),
            keywords: [("1".to_string(), "Error".to_string())]
                .into_iter()
                .collect(),
            opcodes: [("11".to_string(), "Start".to_string())]
                .into_iter()
                .collect(),
            source_os_build: Some(26200),
        };

        let written =
            write_provider_database(&path, std::slice::from_ref(&metadata)).expect("write");
        assert_eq!(written, 1);

        let database = ProviderDb::open(&path).expect("opens");
        let read = database
            .provider("Round-Trip-Provider")
            .expect("query")
            .expect("present");
        assert_eq!(read, metadata);
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

        let event = metadata.event(2, Some(0)).expect("event id 2 is defined");
        let template = event
            .description
            .as_deref()
            .expect("event 2 has a description");
        println!("template: {template}");

        let rendered = render_description(template, &["0x80180005".to_string()]);
        println!("rendered: {}", rendered.text);
        assert!(
            !rendered.text.contains("%1"),
            "the insertion should have been filled: {}",
            rendered.text
        );
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
