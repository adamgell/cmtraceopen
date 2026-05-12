use chrono::Local;
use log::{Level, LevelFilter, Log, Metadata, Record};
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::PathBuf;
use std::sync::Mutex;
use tauri::Manager;

struct FileLogger {
    file: Mutex<File>,
}

impl Log for FileLogger {
    fn enabled(&self, metadata: &Metadata<'_>) -> bool {
        metadata.level() <= Level::Info
    }

    fn log(&self, record: &Record<'_>) {
        if !self.enabled(record.metadata()) {
            return;
        }

        if let Ok(mut file) = self.file.lock() {
            let _ = writeln!(
                file,
                "{} {:<5} {} - {}",
                Local::now().format("%Y-%m-%dT%H:%M:%S%.3f%:z"),
                record.level(),
                record.target(),
                record.args()
            );
        }
    }

    fn flush(&self) {
        if let Ok(mut file) = self.file.lock() {
            let _ = file.flush();
        }
    }
}

pub fn init(app: &tauri::App) -> Result<PathBuf, Box<dyn std::error::Error>> {
    let log_dir = app.path().app_log_dir()?;
    fs::create_dir_all(&log_dir)?;

    let log_path = log_dir.join("cmtrace-open.log");
    let file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log_path)?;

    log::set_boxed_logger(Box::new(FileLogger {
        file: Mutex::new(file),
    }))?;
    log::set_max_level(LevelFilter::Info);

    let default_panic_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |panic_info| {
        log::error!("event=panic panic_info={panic_info}");
        default_panic_hook(panic_info);
    }));

    log::info!("event=app_log_initialized path=\"{}\"", log_path.display());
    Ok(log_path)
}
