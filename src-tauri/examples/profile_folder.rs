//! Quick profiling script for folder parsing performance.
//! Run with: cargo run --release --example profile_folder

use std::time::Instant;

fn main() {
    let folder = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "../Logs".to_string());

    println!("Profiling folder: {folder}");
    println!("---");

    // List files
    let mut files: Vec<_> = std::fs::read_dir(&folder)
        .expect("cannot read folder")
        .filter_map(|e| e.ok())
        .filter(|e| e.path().is_file())
        .collect();
    files.sort_by_key(|e| e.file_name());

    println!("{} files found\n", files.len());

    let mut total_entries = 0usize;
    let mut total_bytes = 0u64;
    let mut total_parse_ms = 0f64;

    for entry in &files {
        let path = entry.path();
        let size = entry.metadata().map(|m| m.len()).unwrap_or(0);
        total_bytes += size;

        let start = Instant::now();
        match app_lib::parser::parse_file(path.to_str().unwrap()) {
            Ok((result, _parser)) => {
                let elapsed = start.elapsed();
                let ms = elapsed.as_secs_f64() * 1000.0;
                total_parse_ms += ms;
                total_entries += result.entries.len();

                let mb = size as f64 / 1024.0 / 1024.0;
                let throughput = mb / elapsed.as_secs_f64();

                println!(
                    "{:50} {:>6.1} MB  {:>6.0} entries  {:>7.1} ms  ({:.0} MB/s)",
                    path.file_name().unwrap().to_str().unwrap(),
                    mb,
                    result.entries.len(),
                    ms,
                    throughput
                );
            }
            Err(e) => {
                println!(
                    "{:50} ERROR: {e}",
                    path.file_name().unwrap().to_str().unwrap()
                );
            }
        }
    }

    println!("\n---");
    println!(
        "Total: {total_entries} entries, {:.1} MB",
        total_bytes as f64 / 1024.0 / 1024.0
    );
    println!("Parse time: {total_parse_ms:.0} ms");
    println!(
        "Throughput: {:.0} MB/s",
        (total_bytes as f64 / 1024.0 / 1024.0) / (total_parse_ms / 1000.0)
    );

    // Now test serialization overhead
    println!("\n--- Serialization overhead ---");
    let path = files.first().unwrap().path();
    let (result, _) = app_lib::parser::parse_file(path.to_str().unwrap()).unwrap();
    let entry_count = result.entries.len();

    let start = Instant::now();
    let json = serde_json::to_string(&result).unwrap();
    let ser_ms = start.elapsed().as_secs_f64() * 1000.0;
    let json_mb = json.len() as f64 / 1024.0 / 1024.0;

    println!("Serialize {entry_count} entries: {ser_ms:.1} ms, {json_mb:.1} MB JSON");

    let start = Instant::now();
    let _: serde_json::Value = serde_json::from_str(&json).unwrap();
    let de_ms = start.elapsed().as_secs_f64() * 1000.0;
    println!("Deserialize: {de_ms:.1} ms");
}
