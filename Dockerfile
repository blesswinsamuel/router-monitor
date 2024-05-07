# https://ebpf-go.dev/guides/getting-started/
FROM golang:latest AS builder

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
RUN ln -sf /usr/include/aarch64-linux-gnu/asm/ /usr/include/asm

WORKDIR /src

COPY go.mod go.sum ./

RUN go mod download

COPY internal ./internal

RUN go generate ./...

COPY . .

RUN go build -o /bin/ebpf-firewall ./cmd/ebpf-firewall

FROM debian:bullseye-slim

COPY --from=builder /bin/ebpf-firewall /bin/ebpf-firewall

CMD ["/bin/ebpf-firewall"]
