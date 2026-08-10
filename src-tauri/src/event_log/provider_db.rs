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
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::{OnceLock, RwLock};

use cmtraceopen_parser::provider::ProviderMetadata;
use flate2::read::GzDecoder;
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
fn inflate_json<T: serde::de::DeserializeOwned + Default>(blob: &[u8]) -> Result<T, String> {
    if blob.is_empty() {
        return Ok(T::default());
    }
    let mut decoder = GzDecoder::new(blob);
    let mut json = String::new();
    decoder
        .read_to_string(&mut json)
        .map_err(|error| format!("provider payload is not valid gzip: {error}"))?;
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
        // a merged database reports nothing rather than an arbitrary one of several builds.
        let source_os_build: Option<u32> = connection
            .query_row(
                "SELECT SourceOsBuild FROM ProviderDetails \
                 GROUP BY SourceOsBuild HAVING COUNT(DISTINCT SourceOsBuild) >= 0 LIMIT 2",
                [],
                |row| row.get(0),
            )
            .ok()
            .filter(|_| {
                connection
                    .query_row(
                        "SELECT COUNT(DISTINCT SourceOsBuild) FROM ProviderDetails",
                        [],
                        |row| row.get::<_, u32>(0),
                    )
                    .map(|distinct| distinct == 1)
                    .unwrap_or(false)
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

// ── Process-wide store ──────────────────────────────────────────────────────

#[derive(Default)]
struct ProviderStore {
    databases: Vec<PathBuf>,
    /// Lowercased provider name to metadata, including negative results so a provider absent from
    /// every database is not looked up again for every event that mentions it.
    cache: HashMap<String, Option<ProviderMetadata>>,
    info: Vec<ProviderDbInfo>,
}

fn store() -> &'static RwLock<ProviderStore> {
    static STORE: OnceLock<RwLock<ProviderStore>> = OnceLock::new();
    STORE.get_or_init(|| RwLock::new(ProviderStore::default()))
}

/// Registers every `.db` in `directory`, replacing any previously registered set.
pub fn load_directory(directory: &Path) -> Result<Vec<ProviderDbInfo>, String> {
    let entries = std::fs::read_dir(directory).map_err(|error| {
        format!(
            "cannot read provider database directory {}: {error}",
            directory.display()
        )
    })?;

    let mut databases = Vec::new();
    let mut info = Vec::new();
    let mut failures = Vec::new();

    let mut paths: Vec<PathBuf> = entries
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| {
            path.is_file()
                && path
                    .extension()
                    .and_then(|extension| extension.to_str())
                    .is_some_and(|extension| extension.eq_ignore_ascii_case("db"))
        })
        .collect();
    paths.sort();

    for path in paths {
        match ProviderDb::open(&path) {
            Ok(database) => {
                info.push(database.info().clone());
                databases.push(path);
            }
            // A file that is not a provider database is reported, not fatal: the directory is
            // user-supplied and may hold anything.
            Err(reason) => failures.push(reason),
        }
    }

    {
        let mut guard = store()
            .write()
            .map_err(|_| "provider store lock was poisoned".to_string())?;
        guard.databases = databases;
        guard.info = info.clone();
        guard.cache.clear();
    }

    if info.is_empty() && !failures.is_empty() {
        return Err(failures.join("; "));
    }
    Ok(info)
}

/// Metadata for `provider_name`, consulting registered databases in order and caching the result.
pub fn provider(provider_name: &str) -> Option<ProviderMetadata> {
    let key = provider_name.to_ascii_lowercase();

    if let Ok(guard) = store().read() {
        if let Some(cached) = guard.cache.get(&key) {
            return cached.clone();
        }
    }

    let paths = match store().read() {
        Ok(guard) => guard.databases.clone(),
        Err(_) => return None,
    };

    let mut found = None;
    for path in paths {
        if let Ok(database) = ProviderDb::open(&path) {
            if let Ok(Some(metadata)) = database.provider(provider_name) {
                found = Some(metadata);
                break;
            }
        }
    }

    if let Ok(mut guard) = store().write() {
        guard.cache.insert(key, found.clone());
    }
    found
}

/// Summary of every registered database.
pub fn registered() -> Vec<ProviderDbInfo> {
    store()
        .read()
        .map(|guard| guard.info.clone())
        .unwrap_or_default()
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

        let info = load_directory(&dir).expect("loads");
        assert_eq!(info.len(), 2);
        assert!(provider("A").is_some());
        assert!(provider("B").is_some());
        assert!(provider("Nobody").is_none());
        assert_eq!(registered().len(), 2);
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
