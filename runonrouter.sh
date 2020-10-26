#!/bin/bash -e

docker build -t blesswinsamuel/network_traffic_exporter:latest .
docker run --rm --entrypoint cat blesswinsamuel/network_traffic_exporter:latest /network_traffic_exporter > /tmp/network_traffic_exporter

ssh -p 2244 pi@router.home.local "sudo killall -9 /tmp/network_traffic_exporter || true"
scp -P 2244 /tmp/network_traffic_exporter pi@router.home.local:/tmp/network_traffic_exporter
ssh -p 2244 pi@router.home.local "sudo -E /tmp/network_traffic_exporter -listen 0.0.0.0:9155 -l4 -interface lan -bpf 'src net 192.168.1.0/24 or dst net 192.168.1.0/24'"
