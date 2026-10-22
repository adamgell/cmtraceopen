/**
 * How the analysis session's timeline is paged, retried and bounded.
 *
 * One definition for everything that pages the timeline: the unified timeline view (its page cache
 * and its retries), the first page the session is created with (event-analysis-session.ts),
 * and the correlation load (its member scan and its retries). They used to repeat these values and
 * a test compared the copies; a number that exists once cannot drift.
 *
 * Pure constants and no imports, so any of them can import this without pulling in a store.
 */

/** Items per timeline page. The engine returns at most 1,000 (`MAX_ANALYSIS_TIMELINE_PAGE_ITEMS`). */
export const EVENT_LOG_TIMELINE_PAGE_SIZE = 1_000;

/** Tries after the first for a failed timeline page, before the load stops and says it is incomplete. */
export const EVENT_LOG_TIMELINE_AUTOMATIC_RETRY_LIMIT = 2;

/** The most serialized timeline bytes one consumer keeps in memory. */
export const EVENT_LOG_TIMELINE_CACHE_BYTE_LIMIT = 24 * 1024 * 1024;
