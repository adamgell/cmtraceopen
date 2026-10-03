# Microsoft Store pilot reference

## Proven RED/GREEN sequence

The pilot used PR #518 head `e3e328999fc4eaf7d5afa9ec12037ffa37a27298` as the exact RED base.

1. Typed-intent RED test: add typed assignment evidence with `Required` and inject caller-writable `named_data` containing `IntuneIntent=notTargeted` into device evidence. The old reducer returned `NotTargeted` instead of `Required`.
2. Input-order RED test: analyze a valid Store Win32 bundle and its reversed artifact order. The old reducer changed coverage, observation, evidence, and output ordering.
3. GREEN fix: only assignment-origin observations may establish intent; artifact units are sorted deterministically while preserving record order within each artifact.

## Verified local commits

- Governance PR #519 amended at `f8d9bb2919174a3ab902d545637a054cc7cfb74a`.
- Typed-intent RED: `43786b4265302798aac7bf6a029aed577ed1b679`.
- Input-order RED: `aa197bb57895c1de4266639af2df21f51008f85e`.
- GREEN implementation: `b2f02bd517a9d4876000e3ee78e169416fe99ac5`.

## Verification pattern

Run the RED tests independently and preserve their real failure output. After implementation, run:

```bash
cargo test --locked -p cmtraceopen-parser --test intune_windows_microsoft_store
cargo clippy --locked -p cmtraceopen-parser --all-targets -- -D warnings
rustfmt --edition 2021 --config skip_children=true --check \
  crates/cmtraceopen-parser/src/intune/apps/windows/microsoft_store/reducer.rs \
  crates/cmtraceopen-parser/tests/intune_windows_microsoft_store.rs
git diff --check
```

The pilot's focused/full Store suite passed 28 tests, Clippy passed, lane-scoped rustfmt passed, and diff checks passed.

## Important scope lesson

The RED tests and GREEN fix were deliberately separated. The GREEN slice changed only the Store reducer and focused Store integration test. No universal reducer abstraction, shared runtime framework, redaction redesign, or unrelated semantic cleanup was introduced.

## Delegation lesson

A delegated child can reach max iterations or fail to return an encrypted summary after doing useful work. Inspect the live transcript and the actual worktree/commit/tests yourself. Accept only verified artifacts and command output, not the child's completion status.
