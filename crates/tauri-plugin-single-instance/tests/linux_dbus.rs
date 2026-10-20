//! Real protocol tests on an owned private bus. No test connects to the user's
//! session bus, even when cargo is run outside dbus-run-session.
#![cfg(unix)]

#[path = "../src/platform_impl/linux/dbus.rs"]
mod transport;

use std::{
    future::Future,
    io::{BufRead, BufReader},
    os::unix::fs::DirBuilderExt,
    path::PathBuf,
    process::{Child, Command, Stdio},
    sync::{
        atomic::{AtomicU64, Ordering},
        mpsc,
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use transport::{claim_or_forward, Instance};

const OBJECT_PATH: &str = "/org/CMTraceOpen/SingleInstanceTest";
const LIMIT: Duration = Duration::from_secs(15);
static NEXT_BUS: AtomicU64 = AtomicU64::new(0);

struct PrivateBus {
    child: Child,
    directory: PathBuf,
    address: String,
}

impl PrivateBus {
    fn new() -> Self {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let directory = PathBuf::from(format!(
            "/tmp/cmtrace-dbus-{}-{nonce}-{}",
            std::process::id(),
            NEXT_BUS.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&directory)
            .unwrap();
        let child = Command::new("dbus-daemon")
            .args(["--session", "--nofork", "--nopidfile", "--print-address=1"])
            .arg(format!("--address=unix:path={}/bus", directory.display()))
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .expect("dbus-daemon is required for private D-Bus transport tests");
        let mut bus = Self {
            child,
            directory,
            address: String::new(),
        };
        let stdout = bus.child.stdout.take().unwrap();
        let (ready, result) = mpsc::channel();
        let reader = std::thread::spawn(move || {
            let mut address = String::new();
            let outcome = BufReader::new(stdout)
                .read_line(&mut address)
                .map(|_| address);
            let _ = ready.send(outcome);
        });
        let outcome = result.recv_timeout(LIMIT);
        if outcome.is_err() {
            bus.stop(); // Closing the owned daemon also unblocks its stdout reader.
        }
        reader.join().unwrap();
        bus.address = outcome.expect("private daemon startup timed out").unwrap();
        bus.address = bus.address.trim().to_owned();
        assert!(
            bus.address.starts_with("unix:"),
            "private daemon did not return a Unix address"
        );
        bus
    }

    fn builder(&self) -> zbus::connection::Builder<'_> {
        zbus::connection::Builder::address(self.address.as_str())
    }

    fn name(&self) -> String {
        format!(
            "org.CMTraceOpen.Test.p{}.n{}",
            std::process::id(),
            NEXT_BUS.fetch_add(1, Ordering::Relaxed)
        )
    }

    fn stop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Drop for PrivateBus {
    fn drop(&mut self) {
        self.stop();
        let _ = std::fs::remove_dir_all(&self.directory);
    }
}

fn run(future: impl Future<Output = ()>) {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap()
        .block_on(async {
            tokio::time::timeout(LIMIT, future)
                .await
                .expect("D-Bus test timed out")
        });
}

fn no_activation() -> transport::Callback {
    Box::new(|_, _| panic!("this test must not activate this interface"))
}

async fn primary(
    bus: &PrivateBus,
    name: &str,
    callback: transport::Callback,
) -> transport::PrimaryInstance {
    match claim_or_forward(
        bus.builder(),
        name,
        OBJECT_PATH,
        callback,
        vec![],
        String::new(),
    )
    .await
    .unwrap()
    {
        Instance::Primary(primary) => primary,
        Instance::Secondary => panic!("the first connection must own the instance name"),
    }
}

struct ChildGuard(Option<Child>);
impl Drop for ChildGuard {
    fn drop(&mut self) {
        if let Some(child) = &mut self.0 {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

#[test]
fn secondary_handoff_is_acknowledged_before_process_exit() {
    let bus = PrivateBus::new();
    let name = bus.name();
    run(async {
        let (send, received) = mpsc::channel();
        let primary = primary(
            &bus,
            &name,
            Box::new(move |args, cwd| {
                send.send((args, cwd)).unwrap();
            }),
        )
        .await;
        let mut child = ChildGuard(Some(
            Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "secondary_process", "--ignored"])
                .env("CMTRACE_TEST_BUS_NAME", &name)
                .env("DBUS_SESSION_BUS_ADDRESS", &bus.address)
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .unwrap(),
        ));
        while child.0.as_mut().unwrap().try_wait().unwrap().is_none() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        let output = child.0.take().unwrap().wait_with_output().unwrap();
        assert!(
            output.status.success(),
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(
            received.try_recv().unwrap(),
            (
                vec![
                    "cmtrace-open".to_owned(),
                    "/tmp/evidence log.log".to_owned(),
                    "relative/second.log".to_owned()
                ],
                "/tmp/launch working directory".to_owned(),
            )
        );
        // The primary service still runs after setup and after a secondary exits.
        let next = claim_or_forward(
            bus.builder(),
            &name,
            OBJECT_PATH,
            no_activation(),
            vec!["again".into()],
            "/second".into(),
        )
        .await
        .unwrap();
        assert!(matches!(next, Instance::Secondary));
        assert_eq!(
            received.try_recv().unwrap(),
            (vec!["again".to_owned()], "/second".to_owned())
        );
        primary.release().await.unwrap();
    });
}

#[test]
#[ignore = "child-process fixture executed by secondary_handoff_is_acknowledged_before_process_exit"]
fn secondary_process() {
    let name =
        std::env::var("CMTRACE_TEST_BUS_NAME").expect("run only as the private-bus child fixture");
    run(async {
        let result = claim_or_forward(
            zbus::connection::Builder::session(),
            &name,
            OBJECT_PATH,
            no_activation(),
            vec![
                "cmtrace-open".into(),
                "/tmp/evidence log.log".into(),
                "relative/second.log".into(),
            ],
            "/tmp/launch working directory".into(),
        )
        .await
        .unwrap();
        assert!(matches!(result, Instance::Secondary));
    });
}

#[test]
fn primary_rejects_name_replacement() {
    let bus = PrivateBus::new();
    let name = bus.name();
    run(async {
        let primary = primary(&bus, &name, no_activation()).await;
        let replacement = bus
            .builder()
            .name(name.as_str())
            .replace_existing_names(true)
            .allow_name_replacements(true)
            .build()
            .await;
        assert!(matches!(replacement, Err(zbus::Error::NameTaken)));
        primary.release().await.unwrap();
    });
}

struct RecordingOwner(mpsc::Sender<(Vec<String>, String)>);
#[zbus::interface(name = "org.SingleInstance.DBus")]
impl RecordingOwner {
    fn execute_callback(&self, argv: Vec<String>, cwd: String) {
        self.0.send((argv, cwd)).unwrap();
    }
}

#[test]
fn secondary_does_not_replace_an_owner_that_allows_replacement() {
    let bus = PrivateBus::new();
    let name = bus.name();
    run(async {
        let (send, received) = mpsc::channel();
        let owner = bus
            .builder()
            .name(name.as_str())
            .allow_name_replacements(true)
            .serve_at(OBJECT_PATH, RecordingOwner(send))
            .build()
            .await
            .unwrap();
        let result = claim_or_forward(
            bus.builder(),
            &name,
            OBJECT_PATH,
            no_activation(),
            vec!["preserved".into()],
            "/cwd".into(),
        )
        .await
        .unwrap();
        assert!(matches!(result, Instance::Secondary));
        assert_eq!(
            received.try_recv().unwrap(),
            (vec!["preserved".to_owned()], "/cwd".to_owned())
        );
        owner.release_name(name.as_str()).await.unwrap();
    });
}

#[test]
fn cleanup_releases_ownership_before_connection_is_dropped() {
    let bus = PrivateBus::new();
    let name = bus.name();
    run(async {
        let old_primary = primary(&bus, &name, no_activation()).await;
        old_primary.release().await.unwrap();
        old_primary.release().await.unwrap();
        let new_primary = primary(&bus, &name, no_activation()).await;
        new_primary.release().await.unwrap();
    });
}

#[test]
fn invalid_names_and_paths_are_errors_not_new_instances() {
    let bus = PrivateBus::new();
    run(async {
        assert!(matches!(
            claim_or_forward(
                bus.builder(),
                "invalid name",
                OBJECT_PATH,
                no_activation(),
                vec![],
                String::new()
            )
            .await,
            Err(transport::ClaimError::Unavailable(_))
        ));
        assert!(matches!(
            claim_or_forward(
                bus.builder(),
                &bus.name(),
                "not/an/object/path",
                no_activation(),
                vec![],
                String::new()
            )
            .await,
            Err(transport::ClaimError::Unavailable(_))
        ));
    });
}

#[test]
fn failed_secondary_activation_is_not_reported_as_success() {
    let bus = PrivateBus::new();
    let name = bus.name();
    run(async {
        let owner = bus.builder().name(name.as_str()).build().await.unwrap();
        assert!(matches!(
            claim_or_forward(
                bus.builder().method_timeout(Duration::from_millis(250)),
                &name,
                OBJECT_PATH,
                no_activation(),
                vec!["must not be lost".into()],
                "/cwd".into()
            )
            .await,
            Err(transport::ClaimError::Delivery(_))
        ));
        owner.release_name(name.as_str()).await.unwrap();
    });
}

#[test]
fn unavailable_bus_does_not_create_a_primary() {
    let bus = PrivateBus::new();
    let address = format!("unix:path={}/missing.socket", bus.directory.display());
    run(async {
        assert!(matches!(
            claim_or_forward(
                zbus::connection::Builder::address(address.as_str()),
                &bus.name(),
                OBJECT_PATH,
                no_activation(),
                vec![],
                String::new()
            )
            .await,
            Err(transport::ClaimError::Unavailable(_))
        ));
    });
}

#[test]
fn cleanup_reports_a_disconnected_bus() {
    let mut bus = PrivateBus::new();
    let name = bus.name();
    run(async {
        let primary = primary(&bus, &name, no_activation()).await;
        bus.stop();
        assert!(primary.release().await.is_err());
    });
}

#[test]
fn tauri_runtime_keeps_primary_alive_after_setup_returns() {
    let bus = PrivateBus::new();
    let name = bus.name();
    let (send, received) = mpsc::channel();
    let owner = tauri::async_runtime::block_on(async {
        tokio::time::timeout(
            LIMIT,
            primary(
                &bus,
                &name,
                Box::new(move |argv, cwd| send.send((argv, cwd)).unwrap()),
            ),
        )
        .await
        .expect("primary setup timed out")
    });
    // A separate block_on models a later process after synchronous setup returns.
    let result = tauri::async_runtime::block_on(async {
        tokio::time::timeout(
            LIMIT,
            claim_or_forward(
                bus.builder(),
                &name,
                OBJECT_PATH,
                no_activation(),
                vec!["after setup".into()],
                "/later".into(),
            ),
        )
        .await
        .unwrap()
        .unwrap()
    });
    assert!(matches!(result, Instance::Secondary));
    assert_eq!(
        received.try_recv().unwrap(),
        (vec!["after setup".to_owned()], "/later".to_owned())
    );
    tauri::async_runtime::block_on(async {
        tokio::time::timeout(LIMIT, owner.release())
            .await
            .expect("primary release timed out")
            .unwrap();
    });
}
