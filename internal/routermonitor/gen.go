package routermonitor

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target amd64 ebpfCollector ebpf-collector.c
