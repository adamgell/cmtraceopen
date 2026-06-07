# crates/parser — external OSS dependency (the upstream seam)

The CMTrace log parser is **not vendored here** — it's consumed as an external
dependency from the open-source CMTrace Open repo. This keeps the open-core
boundary clean and makes parser improvements flow **upstream** with zero friction
(same language, no FFI).

Add it to `app/Cargo.toml` when log features land (Phase 2):

```toml
# git dependency on a pinned commit during early dev
cmtraceopen-parser = { git = "https://github.com/adamgell/cmtraceopen", rev = "<pin>" }

# or, once published:
# cmtraceopen-parser = "x.y"
```

> Rule: bug fixes / new formats go to the OSS crate first, then flow here via a
> version/rev bump. Never fork the parser into this repo.
