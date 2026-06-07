# API contract

`openapi.yaml` is the **single source of truth** for the DTOs and endpoints shared
between the .NET service and the Rust client. Generate types from it on both sides
instead of hand-writing them twice.

## Generate C# (service side)

```bash
# Option A: NSwag
nswag openapi2csclient /input:openapi.yaml /classstyle:Record \
  /namespace:CmProjectX.Contract /output:../service/Api/Contract.g.cs

# Option B: openapi-generator
openapi-generator-cli generate -i openapi.yaml -g aspnetcore -o ../service/Api
```

## Generate Rust (client side)

```bash
# Option A: progenitor (build-time, type-safe client)
#   add a build.rs in crates/api-types that runs progenitor against openapi.yaml
#
# Option B: openapi-generator
openapi-generator-cli generate -i openapi.yaml -g rust -o ../crates/api-types
```

Until codegen is wired, `crates/api-types/src/lib.rs` holds hand-written structs
that mirror these schemas — keep them in sync, or replace them with generated code.
