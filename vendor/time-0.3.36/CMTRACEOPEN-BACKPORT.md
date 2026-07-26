# CMTrace Open security backport

This directory starts from the crates.io `time` 0.3.36 package:

- crates.io checksum: `5dfd88e563464686c916c7e46e623e520ddc6d79fa6641390f2e3fa86e83e885`
- upstream source revision: `3c3c546a661ac59e1a586a4edc65adff04fd1335`
- upstream tag: [`v0.3.36`](https://github.com/time-rs/time/releases/tag/v0.3.36)

CMTrace Open changes one upstream source file,
`src/parsing/combinator/rfc/rfc2822.rs`, by backporting the recursion-depth
limit from upstream commit
[`1c63dc7985b8fa26bd8c689423cc56b7a03841ee`](https://github.com/time-rs/time/commit/1c63dc7985b8fa26bd8c689423cc56b7a03841ee).
That commit is the fix released in `time` 0.3.47 for RUSTSEC-2026-0009.

The fixed upstream release requires Rust 1.88.0, while CMTrace Open's locked
compiler contract is Rust 1.77.2. The root `[patch.crates-io]` override and the
exact `=0.3.36` requirement preserve that contract without ignoring the
advisory. `src-tauri/tests/security_dependencies.rs` verifies the upstream
boundary: 31 nested RFC 2822 comments parse and 32 are rejected.

Because this is a path-patched crate, the lockfile no longer identifies it as
the vulnerable crates.io artifact. Security closure therefore depends on all
of these checks:

1. Keep the source diff against crates.io 0.3.36 limited to the documented
   upstream backport.
2. Run `cargo test -p cmtrace-open --test security_dependencies`.
3. Run `cargo +1.77.2 check --workspace --all-features --locked`.
4. Run `cargo audit` and `cd src-tauri && cargo deny check` to ensure no
   vulnerable registry copy of `time` re-enters the dependency graph.

Remove this backport when CMTrace Open can adopt an upstream fixed `time`
release without raising its compiler contract unintentionally.
