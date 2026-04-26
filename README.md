# Router Monitor

![Screenshot 2023-11-18 at 10 35 17 PM](https://github.com/blesswinsamuel/router-monitor/assets/815723/25391261-ecb0-438a-a1b3-9c61af3f3434)
![Screenshot 2023-11-18 at 10 34 09 PM](https://github.com/blesswinsamuel/router-monitor/assets/815723/1dd72a04-1c39-489c-9a55-0227a6e026e4)


Inspired by https://github.com/zaneclaes/network-traffic-metrics

## Run

```bash
go run ./cmd/router-monitor <network-interface>
```

## Environment Variables

- `HOST`: bind host for metrics endpoint (default: `0.0.0.0`)
- `PORT`: bind port for metrics endpoint (default: `9156`)
- `INTERNET_CONNECTION_CHECK_PING_ADDRS`: comma-separated host:port targets for TCP reachability checks (default: `1.1.1.1:53,8.8.8.8:53`)
- `LAN_SUBNET_CIDR`: local IPv4 subnet used to classify internet vs local traffic in eBPF labels (default: `10.100.0.0/16`)
- `DOMAIN_SUFFIX`: optional suffix to strip from reverse-DNS hostnames (example: `.home.arpa`)
- `ARP_HOST_CACHE_TTL`: TTL for cached ARP reverse-DNS names (default: `30m`)

Example:

```bash
HOST=0.0.0.0 \
PORT=9156 \
LAN_SUBNET_CIDR=192.168.1.0/24 \
INTERNET_CONNECTION_CHECK_PING_ADDRS=1.1.1.1:53,8.8.8.8:53 \
ARP_HOST_CACHE_TTL=10m \
go run ./cmd/router-monitor eth0
```
