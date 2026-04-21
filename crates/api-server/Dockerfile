# syntax=docker/dockerfile:1.7
#
# CMTrace Open — API server image.
#
# Multi-stage build. The builder compiles the `api-server` workspace member;
# the runtime stage is a distroless image so the final container is ~40 MB
# and has no shell, minimizing attack surface.
#
# Build from the repo root (the context needs the full Cargo workspace so
# the api-server can resolve its path deps on common-wire and
# cmtraceopen-parser):
#
#   docker buildx build -f crates/api-server/Dockerfile -t cmtraceopen-api:dev .
#
# Multi-platform (Colima on Apple Silicon builds linux/arm64 natively;
# x86_64 via buildx + qemu when needed):
#
#   docker buildx build --platform linux/arm64,linux/amd64 \
#     -f crates/api-server/Dockerfile -t ghcr.io/adamgell/cmtraceopen-api:<tag> \
#     --push .

# ---- Builder ----------------------------------------------------------------
FROM rust:1.83-slim-bookworm AS builder

WORKDIR /workspace

# System deps cargo may invoke: pkg-config is widely expected; ca-certificates
# is needed for crates.io over HTTPS during the initial fetch (already in
# slim, keeping explicit for clarity).
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      pkg-config \
      ca-certificates \
 && rm -rf /var/lib/apt/lists/*

# Copy the workspace. .dockerignore keeps the context tight (see repo root).
COPY . .

# Release build of just the api-server crate (and its transitive deps:
# common-wire, cmtraceopen-parser). src-tauri is a workspace member but is
# not compiled — `-p api-server` walks only its dep graph.
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/workspace/target \
    cargo build --release --locked -p api-server \
 && cp /workspace/target/release/cmtraceopen-api /usr/local/bin/cmtraceopen-api

# ---- Runtime ----------------------------------------------------------------
FROM gcr.io/distroless/cc-debian12 AS runtime

COPY --from=builder /usr/local/bin/cmtraceopen-api /usr/local/bin/cmtraceopen-api

USER nonroot:nonroot
EXPOSE 8080

ENV CMTRACE_LISTEN_ADDR=0.0.0.0:8080 \
    RUST_LOG=api_server=info,tower_http=info,axum=info,warn

ENTRYPOINT ["/usr/local/bin/cmtraceopen-api"]
