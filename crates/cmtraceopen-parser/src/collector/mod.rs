// Pure parts of the evidence-collection pipeline. The on-device collection
// engine itself (running subprocesses, reading files from disk, writing a
// bundle to a target dir) is native-only and stays in src-tauri/src/collector;
// this crate holds the data types + embedded profile catalog that the engine
// (and the agent, once it lands) both consume.

pub mod env_expand;
pub mod profile;
pub mod types;
