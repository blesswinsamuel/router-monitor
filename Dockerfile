FROM debian:bullseye-slim

# RUN apt-get update && apt-get install -y libpcap-dev && apt-get clean

COPY ./target/aarch64-unknown-linux-gnu/release/router-monitor /router-monitor

ENTRYPOINT [ "/router-monitor" ]
