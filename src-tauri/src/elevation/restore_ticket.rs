//! One-time restore tickets for the elevated child process.
//!
//! The elevated process is started with a single opaque identifier. Everything
//! it is allowed to restore lives in a small, typed, short-lived file under an
//! application-owned per-user directory.
//!
//! The ticket is untrusted input even though it sits in per-user storage: it is
//! bounded, schema-versioned, expiring, and consumed exactly once, and it can
//! request only navigation and source opening — never command execution or a
//! privileged write.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use super::{AppWorkspace, ElevationReason, ElevationValidationError, RestoreTarget};

/// Current ticket schema. A ticket written by another version is rejected, not
/// migrated: the elevated process starts normally instead.
pub const TICKET_SCHEMA_VERSION: u32 = 1;

/// Directory beneath the app's local data directory that holds pending tickets.
pub const TICKET_DIRECTORY: &str = "elevation-restore";

/// How long a ticket stays valid. A UAC prompt the user leaves sitting is the
/// long case; five minutes covers it without leaving a stale ticket around.
pub const TICKET_TTL_MS: i64 = 5 * 60 * 1000;

/// Largest accepted ticket file. The serialized form is a few hundred bytes.
pub const MAX_TICKET_BYTES: u64 = 8 * 1024;

/// Length of the opaque identifier — a hyphenated UUID.
const TICKET_ID_LEN: usize = 36;

/// What the elevated process is permitted to restore.
///
/// Field order is fixed and the struct is `deny_unknown_fields`: a tampered or
/// future ticket is refused rather than partially honoured.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RestoreTicket {
    pub schema_version: u32,
    pub ticket_id: String,
    pub created_at_ms: i64,
    pub origin_pid: u32,
    pub workspace: AppWorkspace,
    pub target: RestoreTarget,
    pub reason: ElevationReason,
    /// Marks the restored request as a retry, so a second failure offers
    /// troubleshooting instead of another elevation prompt.
    ///
    /// Always true on a minted ticket: a ticket exists only because a restart
    /// was requested, so consuming one always means "this is the attempt after
    /// elevation". It is a field rather than an implicit truth so the frontend
    /// reads the loop guard from the ticket rather than inferring it from the
    /// ticket's mere presence.
    pub retry_attempted: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Error)]
#[serde(tag = "kind", rename_all = "camelCase")]
pub enum TicketError {
    #[error("the elevation restore identifier is malformed")]
    MalformedId,
    #[error("the elevation restore ticket was not found")]
    NotFound,
    #[error("the elevation restore ticket is not a regular file")]
    NotARegularFile,
    #[error("the elevation restore ticket exceeds the maximum accepted size")]
    TooLarge,
    #[error("the elevation restore ticket could not be read")]
    Unreadable,
    #[error("the elevation restore ticket could not be written")]
    Unwritable,
    #[error("the elevation restore ticket is malformed")]
    Malformed,
    #[error("the elevation restore ticket schema is unsupported")]
    UnsupportedSchema,
    #[error("the elevation restore ticket has expired")]
    Expired,
    #[error("the elevation restore ticket contents are not valid")]
    InvalidContents,
}

impl From<ElevationValidationError> for TicketError {
    fn from(_: ElevationValidationError) -> Self {
        Self::InvalidContents
    }
}

/// Generate an opaque, unguessable ticket identifier.
pub fn new_ticket_id() -> String {
    uuid::Uuid::new_v4().to_string()
}

/// Accept only a lowercase hyphenated UUID.
///
/// This is what keeps `--elevation-restore=<id>` from ever naming a path: the
/// character set excludes every separator, dot, and drive letter form.
pub fn validate_ticket_id(id: &str) -> Result<(), TicketError> {
    if id.len() != TICKET_ID_LEN {
        return Err(TicketError::MalformedId);
    }
    let valid = id.chars().enumerate().all(|(index, character)| {
        if matches!(index, 8 | 13 | 18 | 23) {
            character == '-'
        } else {
            character.is_ascii_digit() || (character.is_ascii_lowercase() && character <= 'f')
        }
    });
    if valid {
        Ok(())
    } else {
        Err(TicketError::MalformedId)
    }
}

/// The directory pending tickets live in, given the app's local data directory.
pub fn ticket_directory(app_local_data_dir: &Path) -> PathBuf {
    app_local_data_dir.join(TICKET_DIRECTORY)
}

/// Resolve a ticket's path, refusing anything that would escape the directory.
fn ticket_path(directory: &Path, id: &str) -> Result<PathBuf, TicketError> {
    validate_ticket_id(id)?;
    let path = directory.join(format!("{id}.json"));
    // Defence in depth: the validated identifier cannot contain a separator, so
    // this can only fail if `directory` itself was unexpected.
    if path.parent() != Some(directory) {
        return Err(TicketError::MalformedId);
    }
    Ok(path)
}

/// Persist a ticket, returning its identifier for the child command line.
pub fn write_ticket(directory: &Path, ticket: &RestoreTicket) -> Result<String, TicketError> {
    let path = ticket_path(directory, &ticket.ticket_id)?;
    fs::create_dir_all(directory).map_err(|_| TicketError::Unwritable)?;
    let encoded = serde_json::to_vec(ticket).map_err(|_| TicketError::Unwritable)?;
    if encoded.len() as u64 > MAX_TICKET_BYTES {
        return Err(TicketError::TooLarge);
    }
    fs::write(&path, &encoded).map_err(|_| TicketError::Unwritable)?;
    Ok(ticket.ticket_id.clone())
}

/// Delete a ticket that was written for a launch that never happened.
///
/// Best effort: a ticket left behind still expires and is still single-use.
pub fn discard_ticket(directory: &Path, id: &str) {
    if let Ok(path) = ticket_path(directory, id) {
        let _ = fs::remove_file(path);
    }
}

/// Atomically claim and validate a ticket.
///
/// The file is renamed before it is read, so two processes racing the same
/// identifier cannot both restore it — the loser sees `NotFound`. The claim is
/// removed whether or not its contents turn out to be valid, so a malformed or
/// expired ticket cannot be retried.
pub fn consume_ticket(
    directory: &Path,
    id: &str,
    now_ms: i64,
) -> Result<RestoreTicket, TicketError> {
    let path = ticket_path(directory, id)?;

    // Reject symlinks and reparse points before touching the contents: follow a
    // symlink here and an attacker-planted link could redirect the read.
    let metadata = fs::symlink_metadata(&path).map_err(map_missing)?;
    if !metadata.file_type().is_file() {
        return Err(TicketError::NotARegularFile);
    }
    if metadata.len() > MAX_TICKET_BYTES {
        // Remove it: an oversized ticket is never going to become valid.
        let _ = fs::remove_file(&path);
        return Err(TicketError::TooLarge);
    }

    let claim = directory.join(format!("{id}.claim"));
    fs::rename(&path, &claim).map_err(map_missing)?;
    let contents = fs::read_to_string(&claim).map_err(|_| TicketError::Unreadable);
    let _ = fs::remove_file(&claim);
    let contents = contents?;

    let ticket: RestoreTicket =
        serde_json::from_str(&contents).map_err(|_| TicketError::Malformed)?;

    if ticket.schema_version != TICKET_SCHEMA_VERSION {
        return Err(TicketError::UnsupportedSchema);
    }
    if ticket.ticket_id != id {
        return Err(TicketError::InvalidContents);
    }
    if now_ms.saturating_sub(ticket.created_at_ms) > TICKET_TTL_MS || now_ms < ticket.created_at_ms
    {
        return Err(TicketError::Expired);
    }

    // Re-validate the source intent. The ticket was validated when written, but
    // it is read back as untrusted input.
    match &ticket.target {
        RestoreTarget::Workspace => {}
        RestoreTarget::File { path } | RestoreTarget::Folder { path, .. } => {
            super::validate_restore_path(path)?;
        }
        RestoreTarget::KnownSource { source_id } => {
            super::validate_source_id(source_id)?;
        }
    }

    Ok(ticket)
}

/// Remove tickets and abandoned claims older than the TTL.
///
/// Called at startup so a cancelled UAC prompt does not leave files behind.
pub fn prune_expired(directory: &Path) {
    let Ok(entries) = fs::read_dir(directory) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let is_ticket = path
            .extension()
            .is_some_and(|extension| extension == "json" || extension == "claim");
        if !is_ticket {
            continue;
        }
        let Ok(metadata) = entry.metadata() else {
            continue;
        };
        let expired = metadata
            .modified()
            .ok()
            .and_then(|modified| modified.elapsed().ok())
            .map(|elapsed| elapsed.as_millis() as i64 > TICKET_TTL_MS)
            // A file whose mtime cannot be read is pruned rather than kept: it
            // is single-use anyway and a fresh request writes a new one.
            .unwrap_or(true);
        if expired {
            let _ = fs::remove_file(path);
        }
    }
}

fn map_missing(error: io::Error) -> TicketError {
    if error.kind() == io::ErrorKind::NotFound {
        TicketError::NotFound
    } else {
        TicketError::Unreadable
    }
}

/// Build a ticket for a validated request.
pub fn ticket_for(
    workspace: AppWorkspace,
    target: RestoreTarget,
    reason: ElevationReason,
    now_ms: i64,
) -> RestoreTicket {
    RestoreTicket {
        schema_version: TICKET_SCHEMA_VERSION,
        ticket_id: new_ticket_id(),
        created_at_ms: now_ms,
        origin_pid: std::process::id(),
        workspace,
        target,
        reason,
        retry_attempted: true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[cfg(target_os = "windows")]
    const ABSOLUTE_FILE: &str = r"C:\ProgramData\CMTrace\app.log";
    #[cfg(not(target_os = "windows"))]
    const ABSOLUTE_FILE: &str = "/var/log/app.log";

    const NOW: i64 = 1_760_000_000_000;

    fn sample(now_ms: i64) -> RestoreTicket {
        ticket_for(
            AppWorkspace::Log,
            RestoreTarget::File {
                path: PathBuf::from(ABSOLUTE_FILE),
            },
            ElevationReason::AccessDenied,
            now_ms,
        )
    }

    #[test]
    fn generated_identifiers_validate() {
        for _ in 0..32 {
            let id = new_ticket_id();
            assert!(
                validate_ticket_id(&id).is_ok(),
                "generated id {id} rejected"
            );
        }
    }

    #[test]
    fn identifier_validation_rejects_traversal_and_separators() {
        for candidate in [
            "..",
            "../../etc/passwd",
            "a/b",
            "a\\b",
            r"C:\Windows\System32",
            "",
            "short",
            // Correct length and shape but uppercase — the canonical form is lowercase.
            "1487DC30-3BB0-46BF-98EE-76771BD9953E",
            // Correct length, wrong separator positions.
            "1487dc303-bb0-46bf-98ee-76771bd9953e",
            // Correct length and separators, non-hex payload.
            "1487dc30-3bb0-46bf-98ee-76771bd995zz",
        ] {
            assert!(
                validate_ticket_id(candidate).is_err(),
                "identifier {candidate:?} must be rejected"
            );
        }
    }

    #[test]
    fn a_ticket_round_trips_and_is_consumed_once() {
        let directory = TempDir::new().expect("temp dir");
        let ticket = sample(NOW);
        let id = write_ticket(directory.path(), &ticket).expect("write");

        let restored = consume_ticket(directory.path(), &id, NOW + 1_000).expect("consume");
        assert_eq!(restored, ticket);

        // Single use: the second attempt finds nothing.
        assert_eq!(
            consume_ticket(directory.path(), &id, NOW + 1_000).unwrap_err(),
            TicketError::NotFound
        );
    }

    #[test]
    fn a_stale_ticket_is_rejected_and_consumed() {
        let directory = TempDir::new().expect("temp dir");
        let ticket = sample(NOW);
        let id = write_ticket(directory.path(), &ticket).expect("write");

        assert_eq!(
            consume_ticket(directory.path(), &id, NOW + TICKET_TTL_MS + 1).unwrap_err(),
            TicketError::Expired
        );
        // An expired ticket must not survive to be retried.
        assert_eq!(
            consume_ticket(directory.path(), &id, NOW).unwrap_err(),
            TicketError::NotFound
        );
    }

    #[test]
    fn a_ticket_created_in_the_future_is_rejected() {
        let directory = TempDir::new().expect("temp dir");
        let id = write_ticket(directory.path(), &sample(NOW)).expect("write");

        assert_eq!(
            consume_ticket(directory.path(), &id, NOW - 1).unwrap_err(),
            TicketError::Expired
        );
    }

    #[test]
    fn a_schema_mismatch_is_rejected() {
        let directory = TempDir::new().expect("temp dir");
        let mut ticket = sample(NOW);
        ticket.schema_version = TICKET_SCHEMA_VERSION + 1;
        let id = write_ticket(directory.path(), &ticket).expect("write");

        assert_eq!(
            consume_ticket(directory.path(), &id, NOW).unwrap_err(),
            TicketError::UnsupportedSchema
        );
    }

    #[test]
    fn an_unknown_field_is_rejected() {
        let directory = TempDir::new().expect("temp dir");
        let id = new_ticket_id();
        let path = directory.path().join(format!("{id}.json"));
        fs::write(
            &path,
            format!(
                r#"{{"schemaVersion":1,"ticketId":"{id}","createdAtMs":{NOW},"originPid":1,"workspace":"log","target":{{"kind":"workspace"}},"reason":"explicitMenu","retryAttempted":true,"command":"calc.exe"}}"#
            ),
        )
        .expect("write");

        assert_eq!(
            consume_ticket(directory.path(), &id, NOW).unwrap_err(),
            TicketError::Malformed
        );
    }

    #[test]
    fn an_unknown_workspace_is_rejected() {
        let directory = TempDir::new().expect("temp dir");
        let id = new_ticket_id();
        let path = directory.path().join(format!("{id}.json"));
        fs::write(
            &path,
            format!(
                r#"{{"schemaVersion":1,"ticketId":"{id}","createdAtMs":{NOW},"originPid":1,"workspace":"root-shell","target":{{"kind":"workspace"}},"reason":"explicitMenu","retryAttempted":true}}"#
            ),
        )
        .expect("write");

        assert_eq!(
            consume_ticket(directory.path(), &id, NOW).unwrap_err(),
            TicketError::Malformed
        );
    }

    #[test]
    fn a_tampered_relative_path_is_rejected() {
        let directory = TempDir::new().expect("temp dir");
        let id = new_ticket_id();
        let path = directory.path().join(format!("{id}.json"));
        fs::write(
            &path,
            format!(
                r#"{{"schemaVersion":1,"ticketId":"{id}","createdAtMs":{NOW},"originPid":1,"workspace":"log","target":{{"kind":"file","path":"relative.log"}},"reason":"explicitMenu","retryAttempted":true}}"#
            ),
        )
        .expect("write");

        assert_eq!(
            consume_ticket(directory.path(), &id, NOW).unwrap_err(),
            TicketError::InvalidContents
        );
    }

    #[test]
    fn an_identifier_mismatch_is_rejected() {
        let directory = TempDir::new().expect("temp dir");
        let mut ticket = sample(NOW);
        let real_id = ticket.ticket_id.clone();
        ticket.ticket_id = new_ticket_id();
        // Store it under the first identifier while its body claims another.
        let path = directory.path().join(format!("{real_id}.json"));
        fs::write(&path, serde_json::to_vec(&ticket).expect("encode")).expect("write");

        assert_eq!(
            consume_ticket(directory.path(), &real_id, NOW).unwrap_err(),
            TicketError::InvalidContents
        );
    }

    #[test]
    fn an_oversized_ticket_is_rejected_and_removed() {
        let directory = TempDir::new().expect("temp dir");
        let id = new_ticket_id();
        let path = directory.path().join(format!("{id}.json"));
        fs::write(&path, vec![b'a'; (MAX_TICKET_BYTES + 1) as usize]).expect("write");

        assert_eq!(
            consume_ticket(directory.path(), &id, NOW).unwrap_err(),
            TicketError::TooLarge
        );
        assert!(
            !path.exists(),
            "an oversized ticket must not be left behind"
        );
    }

    #[test]
    fn a_missing_ticket_reports_not_found() {
        let directory = TempDir::new().expect("temp dir");
        assert_eq!(
            consume_ticket(directory.path(), &new_ticket_id(), NOW).unwrap_err(),
            TicketError::NotFound
        );
    }

    #[test]
    fn a_malformed_identifier_never_reaches_the_filesystem() {
        let directory = TempDir::new().expect("temp dir");
        assert_eq!(
            consume_ticket(directory.path(), "../../etc/passwd", NOW).unwrap_err(),
            TicketError::MalformedId
        );
    }

    #[test]
    fn discarding_removes_an_unused_ticket() {
        let directory = TempDir::new().expect("temp dir");
        let id = write_ticket(directory.path(), &sample(NOW)).expect("write");

        discard_ticket(directory.path(), &id);

        assert_eq!(
            consume_ticket(directory.path(), &id, NOW).unwrap_err(),
            TicketError::NotFound
        );
    }

    #[test]
    fn a_serialized_ticket_carries_only_approved_fields() {
        let ticket = sample(NOW);
        let value: serde_json::Value = serde_json::to_value(&ticket).expect("serialize");
        let object = value.as_object().expect("object");

        let mut keys: Vec<&str> = object.keys().map(String::as_str).collect();
        keys.sort_unstable();
        assert_eq!(
            keys,
            vec![
                "createdAtMs",
                "originPid",
                "reason",
                "retryAttempted",
                "schemaVersion",
                "target",
                "ticketId",
                "workspace",
            ]
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_symlinked_ticket_is_refused() {
        let directory = TempDir::new().expect("temp dir");
        let secret = directory.path().join("secret.json");
        fs::write(&secret, "{}").expect("write");

        let id = new_ticket_id();
        std::os::unix::fs::symlink(&secret, directory.path().join(format!("{id}.json")))
            .expect("symlink");

        assert_eq!(
            consume_ticket(directory.path(), &id, NOW).unwrap_err(),
            TicketError::NotARegularFile
        );
        assert!(secret.exists(), "the symlink target must be untouched");
    }

    #[test]
    fn ticket_directory_is_namespaced_under_app_data() {
        let directory = ticket_directory(Path::new("/app/data"));
        assert_eq!(directory, Path::new("/app/data").join(TICKET_DIRECTORY));
    }
}
