FROM --platform=$BUILDPLATFORM rust:slim-bullseye AS builder

# RUN apt-get update && apt-get install -y libpcap-dev && apt-get clean

# https://github.com/cross-rs/cross/blob/main/docker/Dockerfile.armv7-unknown-linux-gnueabihf
RUN apt-get update && apt-get install --assume-yes --no-install-recommends \
    g++-arm-linux-gnueabihf

WORKDIR /app
COPY Cargo.toml Cargo.lock ./
RUN mkdir src && echo "// dummy file" > src/lib.rs && cargo fetch

RUN rustup target add armv7-unknown-linux-musleabihf

RUN mkdir .cargo && echo '[target.armv7-unknown-linux-musleabihf]\nlinker = "arm-linux-gnueabihf-ld"' > .cargo/config

# to make future builds faster
RUN cargo build --target=armv7-unknown-linux-musleabihf --release

COPY src ./src

# RUN cargo build --release && mv target/release/router-monitor /bin
# RUN rustup target add armv7-unknown-linux-gnueabihf
# RUN cargo build --target=armv7-unknown-linux-gnueabihf --release
RUN cargo build --target=armv7-unknown-linux-musleabihf --release && mv target/armv7-unknown-linux-musleabihf/release/router-monitor /bin

# FROM alpine:3.17
# RUN apk add libpcap-dev

FROM debian:bullseye-slim

# RUN apt-get update && apt-get install -y libpcap-dev && apt-get clean

COPY --from=builder /bin/router-monitor /router-monitor

ENTRYPOINT [ "/router-monitor" ]
