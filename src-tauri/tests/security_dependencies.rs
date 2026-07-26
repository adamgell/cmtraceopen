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
