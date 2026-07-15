# syntax=docker/dockerfile:1
FROM rust:1-slim-trixie AS builder
WORKDIR /build

# keyring's sync-secret-service backend links system libdbus on Linux (see Cargo.toml).
# libssl-dev: reqwest's default native-tls backend links system OpenSSL via openssl-sys.
RUN apt-get update && apt-get install -y --no-install-recommends \
    libdbus-1-dev libssl-dev pkg-config \
    && rm -rf /var/lib/apt/lists/*

COPY . .
RUN cargo build --release --locked

FROM debian:trixie-slim

# git: zentra ci shells out to `git diff`/`git log` to compute the changed/impact file set.
# ca-certificates: required for TLS to the LLM provider endpoint.
# libdbus-1-3: runtime shared lib for keyring's sync-secret-service backend (see Cargo.toml).
RUN apt-get update && apt-get install -y --no-install-recommends \
    git ca-certificates libdbus-1-3 \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /build/target/release/zentra /usr/local/bin/zentra

ENTRYPOINT ["zentra"]
