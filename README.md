# Router Monitor

Router Monitor is a lightweight network observability tool for Linux routers and gateways. It uses eBPF traffic counters, ARP discovery, and internet reachability checks to expose Prometheus metrics and power Grafana dashboards.

![Screenshot 1](https://github.com/blesswinsamuel/router-monitor/assets/815723/25391261-ecb0-438a-a1b3-9c61af3f3434)
![Screenshot 2](https://github.com/blesswinsamuel/router-monitor/assets/815723/1dd72a04-1c39-489c-9a55-0227a6e026e4)

Inspired by https://github.com/zaneclaes/network-traffic-metrics

## Features

- eBPF-based packet and byte accounting at TC ingress/egress
- Local-vs-internet traffic classification using configurable LAN subnet CIDR
- Device discovery via ARP table with reverse-DNS hostname cache
- Internet connectivity and latency metrics from TCP reachability checks
- Prometheus-native metric output and Grafana dashboard generator
- Graceful shutdown and runtime configuration via environment variables

## Requirements

- Linux host/router
- Kernel support for TC eBPF attach (SchedACT/TCX)
- Privileges required to load and attach eBPF programs
- Go toolchain (for local builds)
- Docker (for generating eBPF artifacts)

## Quick Start

### 1) Run from source

```bash
go run ./cmd/router-monitor <network-interface>
```

Example:

```bash
HOST=0.0.0.0 \
PORT=9156 \
LAN_SUBNET_CIDR=192.168.1.0/24 \
INTERNET_CONNECTION_CHECK_PING_ADDRS=1.1.1.1:53,8.8.8.8:53 \
ARP_HOST_CACHE_TTL=10m \
go run ./cmd/router-monitor eth0
```

### 2) Scrape with Prometheus

Expose and scrape:

```text
http://<router-host>:9156/metrics
```

## Configuration

| Variable | Description | Default |
| --- | --- | --- |
| `HOST` | Bind host for metrics endpoint | `0.0.0.0` |
| `PORT` | Bind port for metrics endpoint | `9156` |
| `INTERNET_CONNECTION_CHECK_PING_ADDRS` | Comma-separated `host:port` TCP targets used for internet checks | `1.1.1.1:53,8.8.8.8:53` |
| `LAN_SUBNET_CIDR` | Local IPv4 subnet used for internet/local label classification | `10.100.0.0/16` |
| `DOMAIN_SUFFIX` | Optional suffix removed from reverse-DNS hostnames | empty |
| `ARP_HOST_CACHE_TTL` | Hostname cache TTL for ARP entries | `30m` |

## Dashboard

The Grafana dashboard source is in `dashboard/router-monitor-dashboard.ts` and generates `dashboard/router-monitor-dashboard.json`.

## Development

Useful commands:

```bash
# Generate eBPF artifacts (Docker-based)
task go-generate

# Build Linux amd64 binary
task go-build

# Run tests
go test ./...

# Run amd64-targeted tests
GOARCH=amd64 go test ./...
```

## Troubleshooting

- If eBPF loading fails, verify kernel support and required privileges.
- If labels are mostly `internet`, verify `LAN_SUBNET_CIDR` matches your LAN.
- If hostnames look stale, lower `ARP_HOST_CACHE_TTL`.

## Contributing

Issues and pull requests are welcome. For substantial changes, open an issue first so scope and design can be aligned.
