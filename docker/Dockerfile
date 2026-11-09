FROM rust:1.89-slim AS builder
WORKDIR /build
COPY Cargo.toml ./
COPY Cargo.lock ./
COPY crates ./crates
RUN cargo build --release --locked --bin identity-proxy

FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY --from=builder /build/target/release/identity-proxy /usr/local/bin/identity-proxy
COPY docker/proxy.toml /etc/identity-proxy/proxy.toml
EXPOSE 8443
USER 10001:10001
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
    CMD ["/usr/local/bin/identity-proxy", "--config", "/etc/identity-proxy/proxy.toml", "--healthcheck"]
ENTRYPOINT ["identity-proxy"]
CMD ["--config", "/etc/identity-proxy/proxy.toml"]
