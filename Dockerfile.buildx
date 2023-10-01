FROM --platform=$BUILDPLATFORM rust:slim-bullseye AS builder

# RUN apt-get update && apt-get install -y libpcap-dev && apt-get clean

# https://github.com/cross-rs/cross/blob/main/docker/Dockerfile.armv7-unknown-linux-gnueabihf
# https://github.com/cross-rs/cross/blob/main/docker/Dockerfile.aarch64-unknown-linux-gnu
RUN apt-get update && apt-get install --assume-yes --no-install-recommends \
    g++-aarch64-linux-gnu libssl-dev pkg-config

WORKDIR /app
COPY Cargo.toml Cargo.lock ./
RUN mkdir src && echo "// dummy file" > src/lib.rs && cargo fetch

RUN rustup target add aarch64-unknown-linux-gnu

# RUN mkdir .cargo && echo '[target.aarch64-unknown-linux-gnu]\nlinker = "arm-linux-gnueabihf-ld"' > .cargo/config

# to make future builds faster
RUN cargo build --target=aarch64-unknown-linux-gnu --release

COPY src ./src

# RUN cargo build --release && mv target/release/router-monitor /bin
# RUN rustup target add armv7-unknown-linux-gnueabihf
# RUN cargo build --target=armv7-unknown-linux-gnueabihf --release
RUN cargo build --target=aarch64-unknown-linux-gnu --release && mv target/aarch64-unknown-linux-gnu/release/router-monitor /bin

# FROM alpine:3.17
# RUN apk add libpcap-dev

FROM debian:bullseye-slim

# RUN apt-get update && apt-get install -y libpcap-dev && apt-get clean

COPY --from=builder /bin/router-monitor /router-monitor

ENTRYPOINT [ "/router-monitor" ]
