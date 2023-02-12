FROM golang:bullseye AS builder

RUN apt-get update && apt-get install -y libpcap-dev && apt-get clean

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY internal ./internal
COPY main.go ./
RUN go build .

# FROM alpine:3.17
# RUN apk add libpcap-dev

FROM debian:bullseye-slim

RUN apt-get update && apt-get install -y libpcap-dev && apt-get clean

COPY --from=builder /app/router-monitor /router-monitor

ENTRYPOINT [ "/router-monitor" ]
