# syntax=docker/dockerfile:1
FROM rust:1-slim-trixie AS builder
WORKDIR /build

# keyring's sync-secret-service backend links system libdbus on Linux (see Cargo.toml).
RUN apt-get update && apt-get install -y --no-install-recommends \
    libdbus-1-dev pkg-config \
    && rm -rf /var/lib/apt/lists/*

COPY . .
RUN cargo build --release --locked

FROM debian:trixie-slim

# git: zentra ci shells out to `git diff`/`git log` to compute the changed/impact file set.
# ca-certificates: required for TLS to the LLM provider endpoint.
RUN apt-get update && apt-get install -y --no-install-recommends \
    git ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /build/target/release/zentra /usr/local/bin/zentra

ENTRYPOINT ["zentra"]
