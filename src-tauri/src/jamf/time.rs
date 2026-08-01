//! Timestamp normalization for the JAMF log parsers.

use chrono::{DateTime, LocalResult, NaiveDateTime, TimeZone, Utc};

/// Resolves a naive local timestamp to a UTC instant.
///
/// `jamf.log` (syslog style) and `selfservice.log` both record the host's local
/// wall clock with no offset, so treating the naive value as UTC — as this
/// module previously did — skewed every event by the local offset and made JAMF
/// events unalignable with sources that do carry an offset.
///
/// The log carries no zone, so the host's current zone is the only signal
/// available. Two edge cases have to be chosen explicitly:
///
/// * **Ambiguous** (the repeated hour when DST ends): take the earlier instant,
///   which keeps a log read top-to-bottom monotonic.
/// * **Nonexistent** (the skipped hour when DST begins): the clock time never
///   occurred locally, so fall back to interpreting it as UTC rather than
///   inventing a nearby instant and silently misreporting it.
pub fn local_naive_to_utc(naive: NaiveDateTime) -> DateTime<Utc> {
    match chrono::Local.from_local_datetime(&naive) {
        LocalResult::Single(dt) => dt.with_timezone(&Utc),
        LocalResult::Ambiguous(earliest, _) => earliest.with_timezone(&Utc),
        LocalResult::None => Utc.from_utc_datetime(&naive),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{NaiveDate, Offset};

    #[test]
    fn converts_using_the_host_offset() {
        let naive = NaiveDate::from_ymd_opt(2026, 4, 29)
            .unwrap()
            .and_hms_opt(13, 23, 4)
            .unwrap();
        let utc = local_naive_to_utc(naive);

        // Whatever zone the test host is in, the result must differ from the
        // naive value by exactly that zone's offset at that instant.
        let offset = chrono::Local
            .offset_from_local_datetime(&naive)
            .earliest()
            .expect("host offset")
            .fix()
            .local_minus_utc();
        let expected = Utc.from_utc_datetime(&naive) - chrono::Duration::seconds(offset as i64);
        assert_eq!(utc, expected);
    }

    #[test]
    fn is_monotonic_across_ordered_input() {
        let day = NaiveDate::from_ymd_opt(2026, 7, 30).unwrap();
        let a = local_naive_to_utc(day.and_hms_opt(1, 0, 0).unwrap());
        let b = local_naive_to_utc(day.and_hms_opt(2, 0, 0).unwrap());
        assert!(a < b, "{a} should precede {b}");
    }
}
