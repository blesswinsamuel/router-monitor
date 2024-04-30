# https://ebpf-go.dev/guides/getting-started/
FROM golang:latest

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

RUN ln -sf /usr/include/asm-generic/ /usr/include/asm

WORKDIR /src

COPY go.mod go.sum ./

RUN go mod download

COPY . .

RUN go generate ./...

RUN go build -o /bin/router-monitor

CMD ["/bin/router-monitor"]
