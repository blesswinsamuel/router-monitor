build:
    cross build --release --target aarch64-unknown-linux-gnu
    
    # arm-unknown-linux-gnueabihf

runonrouter:
    #!/bin/bash -e

    podman build -t blesswinsamuel/router-monitor:latest .
    podman run --rm --entrypoint cat blesswinsamuel/router-monitor:latest /router-monitor > /tmp/router-monitor
    chmod +x /tmp/router-monitor

    ssh router "sudo killall -9 /tmp/router-monitor || true"
    scp /tmp/router-monitor router:/tmp/router-monitor
    # ssh router "sudo -E /tmp/router-monitor -listen 0.0.0.0:9156 -interface lan -bpf 'src net 192.168.1.0/24 or dst net 192.168.1.0/24'"
    # ssh router "sudo -E /tmp/router-monitor --bind-addr 0.0.0.0:9156 --interface lan"
