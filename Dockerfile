# https://ebpf-go.dev/guides/getting-started/
FROM --platform=amd64 golang:latest AS builder

RUN apt-get update && apt-get install -y \
    clang \
    llvm \
    libbpf-dev \
    # libelf-dev \
    # libpcap-dev \
    # libssl-dev \
    # libz-dev \
    # pkg-config \
    && rm -rf /var/lib/apt/lists/*

# FROM golang:alpine

# RUN apk add --no-cache \
#     clang \
#     llvm \
#     linux-headers \
#     libbpf-dev \
#     ;

# RUN ln -sf /usr/include/asm-generic/ /usr/include/asm
# RUN ln -sf /usr/include/aarch64-linux-gnu/asm/ /usr/include/asm
RUN ln -sf /usr/include/x86_64-linux-gnu/asm/ /usr/include/asm

WORKDIR /src

COPY go.mod go.sum ./

RUN go mod download

COPY internal ./internal

RUN go generate ./...

COPY cmd ./cmd

RUN go build -o /bin/router-monitor ./cmd/router-monitor

FROM debian:bullseye-slim

COPY --from=builder /bin/router-monitor /bin/router-monitor

CMD ["/bin/router-monitor"]
