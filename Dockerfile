FROM rust:alpine AS build

WORKDIR /build
COPY . .

RUN \
  --mount=type=cache,id=cargo-registry,target=/usr/local/cargo/registry \
  --mount=type=cache,id=cargo-git,target=/usr/local/cargo/git \
  cargo build --locked --release

FROM alpine:latest

COPY --from=build /build/target/release/rustysocks /usr/local/bin

EXPOSE 1080
ENTRYPOINT ["/usr/local/bin/rustysocks", "-l", "0.0.0.0"]
CMD []
