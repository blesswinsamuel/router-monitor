# https://ebpf-go.dev/guides/getting-started/
FROM rust:latest

# RUN apt-get update && apt-get install -y \
#     bpftool \
#     lsb-release wget software-properties-common gnupg \
#     # libbpf-dev \
#     # libelf-dev \
#     # libpcap-dev \
#     # libssl-dev \
#     # libz-dev \
#     # pkg-config \
#     && rm -rf /var/lib/apt/lists/*

RUN rustup install stable
RUN rustup toolchain install nightly --component rust-src

# RUN bash -c "$(wget -O - https://apt.llvm.org/llvm.sh)"
# RUN wget https://apt.llvm.org/llvm.sh && chmod +x llvm.sh && ./llvm.sh 18 && rm llvm.sh
RUN apt-get update && \
    apt-get install -y lsb-release wget software-properties-common gnupg && \
    add-apt-repository -y 'deb http://apt.llvm.org/bookworm/ llvm-toolchain-bookworm-18 main' && \
    add-apt-repository -y 'deb-src http://apt.llvm.org/bookworm/ llvm-toolchain-bookworm-18 main' && \
    wget -qO- https://apt.llvm.org/llvm-snapshot.gpg.key | tee /etc/apt/trusted.gpg.d/apt.llvm.org.asc && \
    apt-get update && \
    # apt-get install -y clang-18 lldb-18 lld-18 clangd-18 && \
    # https://github.com/aya-rs/bpf-linker/blob/373ae3e8d5aeb83908a0d81c9456ddd2a89edb78/README.md?plain=1#L37
    apt-get install -y llvm-18-dev libclang-18-dev libpolly-18-dev && \
    rm -rf /var/lib/apt/lists/*
# RUN apt-key list 2> /dev/null | grep -i llvm
# RUN apt-key del AF4F7421

RUN cargo install --no-default-features bpf-linker
# RUN cargo install bpf-linker

# RUN ln -sf /usr/include/asm-generic/ /usr/include/asm

WORKDIR /src

COPY . .

RUN cargo xtask build-ebpf

RUN RUST_LOG=info cargo build
# --release

# CMD ["/bin/router-monitor"]
