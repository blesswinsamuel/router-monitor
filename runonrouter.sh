#!/bin/bash -e

docker build -t blesswinsamuel/network_traffic_exporter:latest .
docker run --rm --entrypoint cat blesswinsamuel/network_traffic_exporter:latest /app/network_traffic_exporter > /tmp/network_traffic_exporter

scp -P 2244 /tmp/network_traffic_exporter pi@router.home.local:/tmp/network_traffic_exporter
ssh -p 2244 pi@router.home.local "sudo -E /tmp/network_traffic_exporter -listen 0.0.0.0:9154 -interface wan"
