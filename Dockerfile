FROM debian:bullseye-slim

# RUN apt-get update && apt-get install -y libpcap-dev && apt-get clean

COPY ./target/aarch64-unknown-linux-gnu/release/router-monitor /router-monitor

# https://github.com/cross-rs/cross/issues/119#issuecomment-333534345
ENV SSL_CERT_DIR /etc/ssl/certs

ENTRYPOINT [ "/router-monitor" ]
