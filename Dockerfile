FROM golang:buster AS builder

RUN apt-get update && apt-get install -y gcc-arm-linux-gnueabi byacc flex wget make

ENV PCAPV=1.9.1
WORKDIR /libpcap
RUN wget http://www.tcpdump.org/release/libpcap-$PCAPV.tar.gz \
    && tar xvf libpcap-$PCAPV.tar.gz \
    && cd libpcap-$PCAPV \
    && CC='arm-linux-gnueabi-gcc' ./configure --host=arm-linux --with-pcap=linux \
    && make

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY *.go ./
RUN env CC=arm-linux-gnueabi-gcc CGO_ENABLED=1 GOOS=linux GOARCH=arm CGO_CFLAGS="-I/libpcap/libpcap-$PCAPV" CGO_LDFLAGS="-L/libpcap/libpcap-$PCAPV" go build .

FROM alpine

COPY --from=builder /app/network_traffic_exporter /network_traffic_exporter
