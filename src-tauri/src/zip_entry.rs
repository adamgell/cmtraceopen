//! Entry-type facts that the ZIP readers (ESP evidence archives and Event Log bundles) share.

use std::io::Read;

/// Returns a ZIP entry's Unix mode, taking the stored mode bits over any host-specific
/// guess.
///
/// The high 16 bits of the external attributes hold a Unix mode whenever the archiver
/// wrote one, and for a DOS-host entry (version-made-by host 0) they are the only place a
/// symlink or special file is recorded. zip 9's `unix_mode()` ignores them for DOS-host
/// entries and derives a regular-file or directory mode from the DOS attribute byte, so a
/// stored symlink would read as a regular file. This takes the stored bits whenever they
/// are nonzero, for every host, and otherwise falls back to `unix_mode()`. That is the
/// classification zip 8.6 made.
pub(crate) fn stored_unix_mode<R: Read>(entry: &zip::read::ZipFile<'_, R>) -> Option<u32> {
    match entry.external_attributes() >> 16 {
        0 => entry.unix_mode(),
        stored => Some(stored),
    }
}

#[cfg(test)]
mod tests {
    use super::stored_unix_mode;
    use std::io::{Cursor, Write};

    /// Builds a one-entry ZIP whose central-directory header carries `host` and
    /// `external_attributes`, and returns `stored_unix_mode` for that entry.
    fn mode_for(host: u8, external_attributes: u32) -> Option<u32> {
        let mut writer = zip::ZipWriter::new(Cursor::new(Vec::new()));
        writer
            .start_file("member.log", zip::write::SimpleFileOptions::default())
            .expect("start fixture entry");
        writer.write_all(b"content").expect("write fixture entry");
        let mut bytes = writer.finish().expect("finish fixture").into_inner();
        let central = bytes
            .windows(4)
            .rposition(|signature| signature == [0x50, 0x4b, 0x01, 0x02])
            .expect("find central directory header");
        bytes[central + 5] = host;
        bytes[central + 38..central + 42].copy_from_slice(&external_attributes.to_le_bytes());

        let mut archive = zip::ZipArchive::new(Cursor::new(bytes)).expect("open fixture");
        let entry = archive.by_index(0).expect("open fixture entry");
        stored_unix_mode(&entry)
    }

    #[test]
    fn stored_mode_bits_decide_the_type_the_way_zip_8_6_did() {
        const DOS: u8 = 0;
        const UNIX: u8 = 3;
        const NTFS: u8 = 10;
        let cases = [
            // Nonzero stored bits win for every host, special bits included.
            (DOS, 0o120777 << 16, Some(0o120777), "DOS-host symlink"),
            (DOS, 0o010644 << 16, Some(0o010644), "DOS-host FIFO"),
            (
                DOS,
                (0o100644 << 16) | 0x10,
                Some(0o100644),
                "DOS-host regular file with the DOS directory bit",
            ),
            (
                UNIX,
                0o104755 << 16,
                Some(0o104755),
                "Unix-host setuid file",
            ),
            (NTFS, 0o120777 << 16, Some(0o120777), "NTFS-host symlink"),
            // Zero stored bits fall back to the host's own rules.
            (DOS, 0x10, Some(0o040775), "DOS directory bit"),
            (DOS, 0x01, Some(0o100444), "DOS read-only bit"),
            (UNIX, 0x20, Some(0), "Unix host without stored bits"),
            (NTFS, 0x20, None, "other host without stored bits"),
            (DOS, 0, None, "no attributes"),
        ];
        for (host, external_attributes, expected, label) in cases {
            assert_eq!(mode_for(host, external_attributes), expected, "{label}");
        }
    }
}
