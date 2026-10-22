use super::parse_forwarded_open_request;

#[test]
fn unavailable_directory_keeps_only_absolute_arguments() {
    let absolute = std::env::temp_dir().join("second launch absolute.log");
    let absolute = absolute.to_str().expect("absolute UTF-8 test path");
    let request = parse_forwarded_open_request(
        ["cmtrace-open", "relative file.log", absolute, "other.log"].map(String::from),
        "",
    );
    assert_eq!(request.paths, [absolute]);
}

#[test]
fn unavailable_directory_rejects_all_relative_arguments() {
    let request = parse_forwarded_open_request(
        ["cmtrace-open", "relative file.log", "nested/other.log"].map(String::from),
        "",
    );
    assert!(request.paths.is_empty());
}

#[test]
fn known_directory_resolves_relative_arguments() {
    let directory = std::env::temp_dir().join("second launch directory");
    let request = parse_forwarded_open_request(
        ["cmtrace-open", "relative file.log"].map(String::from),
        directory.to_str().expect("absolute UTF-8 test directory"),
    );
    assert_eq!(
        request.paths,
        [directory
            .join("relative file.log")
            .to_str()
            .expect("absolute UTF-8 test path")]
    );
}
