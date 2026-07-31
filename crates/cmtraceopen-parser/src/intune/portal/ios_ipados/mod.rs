// iOS / iPadOS Company Portal artifacts.
//
// iOS and iPadOS do not expose an on-device Company Portal log file to a support engineer.
// The documented Microsoft workflow instead captures the device's log stream from a
// tethered Mac using the macOS Console app, and produces a plain-text export.

pub mod company_portal;
