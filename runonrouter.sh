#!/bin/bash -e

docker build -t blesswinsamuel/router-monitor:latest .
docker run --rm --entrypoint cat blesswinsamuel/router-monitor:latest /router-monitor > /tmp/router-monitor
chmod +x /tmp/router-monitor

ssh -p 2244 pi@router.home.local "sudo killall -9 /tmp/router-monitor || true"
scp -P 2244 /tmp/router-monitor pi@router.home.local:/tmp/router-monitor
ssh -p 2244 pi@router.home.local "sudo -E /tmp/router-monitor -listen 0.0.0.0:9155 -interface lan -bpf 'src net 192.168.1.0/24 or dst net 192.168.1.0/24'"
