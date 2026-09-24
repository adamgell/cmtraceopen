//! What to do when a batched fetch from the Event Log service fails.
//!
//! The decision lives here, apart from the call that produces the error, because everything around
//! it is Windows-only and therefore untestable anywhere else. Getting this wrong is expensive in a
//! specific way: the previous behaviour treated every failure as the end of the channel, so a
//! service that refused one request returned a partial channel that the caller reported as whole.
//! That is not a crash, it is a quiet wrong answer, and only a test that can run everywhere will
//! keep catching it.

/// Windows `ERROR_NO_MORE_ITEMS`: the channel is exhausted. Not a failure.
const NO_MORE_ITEMS: u32 = 259;

/// Windows `RPC_S_INVALID_BOUND`: the service refused the size of the request.
///
/// Seen from `EvtNext` with a 256-handle batch, on one channel out of roughly twelve hundred on a
/// real machine. It says nothing about the channel's contents, so a smaller request is the right
/// answer rather than giving up on the channel.
const INVALID_BOUND: u32 = 1734;

/// How a failed fetch should be handled.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FetchFailure {
    /// The channel is fully read. Stop, and report nothing missing.
    Exhausted,
    /// Retry this fetch with a smaller batch.
    RetryWith(usize),
    /// Stop, and report that the channel was read only in part.
    Truncated,
}

/// Decides how to respond to a failed fetch of `batch` events.
///
/// `floor` is the smallest batch worth attempting. Below it the request is as small as it is going
/// to get, and a further failure is about the channel rather than the request size.
pub fn classify_fetch_failure(win32_code: u32, batch: usize, floor: usize) -> FetchFailure {
    if win32_code == NO_MORE_ITEMS {
        return FetchFailure::Exhausted;
    }
    if win32_code == INVALID_BOUND && batch > floor {
        // Halved rather than dropped straight to the floor, so a channel that can serve 128 is not
        // read at 8 for the rest of the scan.
        return FetchFailure::RetryWith((batch / 2).max(floor));
    }
    FetchFailure::Truncated
}

#[cfg(test)]
mod tests {
    use super::*;

    const FLOOR: usize = 8;

    #[test]
    fn an_exhausted_channel_is_not_a_failure() {
        assert_eq!(
            classify_fetch_failure(NO_MORE_ITEMS, 256, FLOOR),
            FetchFailure::Exhausted
        );
    }

    #[test]
    fn a_refused_batch_size_is_retried_smaller() {
        assert_eq!(
            classify_fetch_failure(INVALID_BOUND, 256, FLOOR),
            FetchFailure::RetryWith(128)
        );
    }

    #[test]
    fn halving_stops_at_the_floor_rather_than_reaching_zero() {
        // A batch of zero would ask for no events and loop forever without reading anything.
        assert_eq!(
            classify_fetch_failure(INVALID_BOUND, 9, FLOOR),
            FetchFailure::RetryWith(FLOOR)
        );
    }

    #[test]
    fn a_refusal_at_the_floor_is_reported_as_truncation() {
        // The request is already as small as it gets, so the problem is not its size. Reporting
        // Exhausted here would present a partly read channel as a complete one.
        assert_eq!(
            classify_fetch_failure(INVALID_BOUND, FLOOR, FLOOR),
            FetchFailure::Truncated
        );
    }

    #[test]
    fn any_other_error_truncates_rather_than_looking_like_the_end_of_the_channel() {
        // ERROR_ACCESS_DENIED partway through a channel is the case that matters: the events after
        // it are missing, and calling that "exhausted" is the silent wrong answer.
        for code in [5u32, 87, 1500, 0] {
            assert_eq!(
                classify_fetch_failure(code, 256, FLOOR),
                FetchFailure::Truncated,
                "win32 {code} must not be mistaken for the end of the channel"
            );
        }
    }

    #[test]
    fn repeated_halving_walks_down_to_the_floor_and_then_stops() {
        // The loop this models must terminate. Following the decisions from a full batch has to
        // reach Truncated in a bounded number of steps rather than retrying forever.
        let mut batch = 256;
        let mut steps = 0;
        loop {
            match classify_fetch_failure(INVALID_BOUND, batch, FLOOR) {
                FetchFailure::RetryWith(next) => {
                    assert!(next < batch, "a retry must shrink the request");
                    batch = next;
                }
                FetchFailure::Truncated => break,
                FetchFailure::Exhausted => panic!("a refusal is not an exhausted channel"),
            }
            steps += 1;
            assert!(steps < 20, "halving should reach the floor quickly");
        }
        assert_eq!(batch, FLOOR);
    }
}
