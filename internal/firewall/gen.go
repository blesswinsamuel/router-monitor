package firewall

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target amd64 ebpfFirewall ebpf_firewall.c
