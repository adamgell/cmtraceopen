use cmtraceopen_parser::{
    models::log_entry::LogFormat,
    parser::{parse_content_with_selection, ResolvedParser},
};

const CAPPED_CONTENT: &[u8] = include_bytes!(
    "fixtures/sccm/client/intake/capped/evidence/client-content/current/DataTransferService.log"
);

#[test]
fn capped_client_content_is_an_exact_incomplete_ccm_prefix() {
    assert_eq!(CAPPED_CONTENT.len(), 128);

    let content = std::str::from_utf8(CAPPED_CONTENT).expect("fixture is declared UTF-8");
    assert!(content.starts_with("<![LOG[SYNTHETIC FIXTURE"));
    assert!(content.contains("error-looking 0x80000001"));
    assert!(!content.contains("[cut]"));

    let parsed =
        parse_content_with_selection(content, "DataTransferService.log", &ResolvedParser::ccm());

    assert_eq!(parsed.total_lines, 1);
    assert_eq!(parsed.parse_errors, 1);
    assert_eq!(parsed.entries.len(), 1);
    assert_eq!(parsed.entries[0].format, LogFormat::Plain);
}
