//! cmProjectX — WinUI 3 + Rust (Windows Reactor) client.
//!
//! This skeleton's `main` just confirms it can reach the local service. The
//! real UI is a Windows Reactor app; the intended shape is sketched below.
//!
//! ```ignore
//! // Reactor: UI as a pure function of state (component + hooks).
//! fn app(cx: &mut RenderCx) -> Element {
//!     nav_view((
//!         nav_item("Timeline", timeline_workspace),  // audit time-machine (MVP)
//!         nav_item("Drift",    drift_workspace),      // snapshot diff
//!         nav_item("Search",   search_workspace),     // unified search
//!         nav_item("Logs",     logs_workspace),       // Phase 2: CMTrace parser
//!     )).into()
//! }
//!
//! fn timeline_workspace(cx: &mut RenderCx) -> Element {
//!     // use_resource loads from ApiClient::audit(); render a virtualized ListView.
//!     let events = cx.use_resource(|| api().audit(None));
//!     list_view(events).into()
//! }
//! ```

mod api_client;
use api_client::ApiClient;

const SERVICE_URL: &str = "http://127.0.0.1:5099";

#[tokio::main]
async fn main() {
    let client = ApiClient::new(SERVICE_URL);

    match client.health().await {
        Ok(status) => println!("service healthy: {status:?}"),
        Err(e) => eprintln!(
            "could not reach service at {SERVICE_URL}: {e}\n\
             start it with: cd service && dotnet run --project Api"
        ),
    }

    // TODO (Phase 0): replace this with the Windows Reactor app entry point
    // and validate LogGrid + live-tail virtualized scrolling before building out.
}
