use time::{format_description::well_known::Rfc2822, OffsetDateTime};

fn rfc2822_with_nested_comment(depth: usize) -> String {
    format!(
        "Fri, 21 Nov 1997 09:55:06 -0600 {}comment{}",
        "(".repeat(depth),
        ")".repeat(depth)
    )
}

#[test]
fn rfc2822_comment_nesting_is_bounded() {
    let accepted = rfc2822_with_nested_comment(31);
    assert!(
        OffsetDateTime::parse(&accepted, &Rfc2822).is_ok(),
        "the upstream boundary must continue to accept 31 nested comments"
    );

    let rejected = rfc2822_with_nested_comment(32);
    assert!(
        OffsetDateTime::parse(&rejected, &Rfc2822).is_err(),
        "RUSTSEC-2026-0009: 32 nested comments must be rejected before recursion can grow unchecked"
    );
}

fn locked_versions(name: &str) -> Vec<&'static str> {
    let name_line = format!("name = \"{name}\"");
    include_str!("../../Cargo.lock")
        .split("[[package]]")
        .filter(|package| package.lines().any(|line| line == name_line))
        .map(|package| {
            package
                .lines()
                .find_map(|line| line.strip_prefix("version = \"")?.strip_suffix('"'))
                .expect("a locked package has a version")
        })
        .collect()
}

fn stable_version(version: &str) -> (u32, u32, u32) {
    let mut parts = version.split('.').map(|part| part.parse::<u32>().unwrap());
    let result = (
        parts.next().unwrap(),
        parts.next().unwrap(),
        parts.next().unwrap(),
    );
    assert!(parts.next().is_none(), "expected a stable release version");
    result
}

#[test]
fn security_lockfile_has_no_vulnerable_zip_for_any_platform() {
    // Cargo.lock includes Windows-only updater dependencies even on macOS/Linux.
    // Checking every resolution catches re-enabled legacy ZIP transport as well
    // as vulnerable direct archive readers.
    let versions = locked_versions("zip");
    assert!(!versions.is_empty(), "the archive readers require ZIP");
    for version in versions {
        assert!(
            stable_version(version) >= (9, 0, 0),
            "RUSTSEC-2026-0367/0368/0369: vulnerable ZIP {version} remains"
        );
    }
}

#[test]
fn security_lockfile_has_patched_rustls_for_any_platform() {
    let versions = locked_versions("rustls");
    assert!(!versions.is_empty(), "the updater retains Rustls TLS");
    for version in versions {
        assert!(
            stable_version(version) >= (0, 23, 46),
            "RUSTSEC-2026-0346/0347/0348/0349: vulnerable Rustls {version} remains"
        );
    }
}

#[test]
fn linux_single_instance_uses_the_maintained_zbus_family() {
    let versions = locked_versions("zbus");
    assert!(!versions.is_empty(), "Linux single-instance requires D-Bus");
    for version in versions {
        assert!(
            stable_version(version) >= (6, 0, 0),
            "the single-instance backend must use maintained zbus, found {version}"
        );
    }
    for package in ["zvariant", "zbus_names", "zvariant_derive"] {
        assert!(
            locked_versions(package).is_empty(),
            "RUSTSEC-2026-0370/0371/0372: unmaintained standalone {package} remains"
        );
    }
}
