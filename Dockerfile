FROM rust:latest AS build

WORKDIR /build
COPY Cargo.toml Cargo.lock .
COPY src src

RUN cargo build --release

FROM debian:trixie-slim

COPY --from=build /build/target/release/rustysocks /usr/local/bin

EXPOSE 1080
ENTRYPOINT ["/usr/local/bin/rustysocks"]
CMD ["-l", "0.0.0.0"]
