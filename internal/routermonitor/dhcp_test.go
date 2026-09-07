package routermonitor

import (
	"os"
	"path/filepath"
	"testing"
)

func TestKeaCSVParser(t *testing.T) {
	keaData := `address,hwaddr,client_id,valid_lifetime,expire,subnet_id,fqdn_fwd,fqdn_rev,hostname,state,user_context,pool_id
10.100.50.69,98:77:D5:2C:10:A8,01:98:77:d5:2c:10:a8,28800,1788767560,50,0,0,wiz2c10a8,0,,0
10.100.99.153,EE:41:6B:C8:F9:9D,01:ee:41:6b:c8:f9:9d,28800,1788764898,99,0,0,iphone.,0,,0
10.100.99.200,AA:BB:CC:DD:EE:FF,01:aa:bb:cc:dd:ee:ff,28800,1000000000,99,0,0,expired-device,2,,0
`
	tmpDir := t.TempDir()
	leasePath := filepath.Join(tmpDir, "dhcp4.leases")
	if err := os.WriteFile(leasePath, []byte(keaData), 0644); err != nil {
		t.Fatalf("write file: %v", err)
	}

	reader := NewDHCPLeaseReader(leasePath, "kea")
	leases, err := reader.GetLeases()
	if err != nil {
		t.Fatalf("GetLeases error: %v", err)
	}

	// Expired / state 2 should be skipped
	if len(leases) != 2 {
		t.Fatalf("expected 2 active leases, got %d", len(leases))
	}

	byIP, byMAC, err := reader.GetLeasesMap()
	if err != nil {
		t.Fatalf("GetLeasesMap error: %v", err)
	}

	l1, ok := byIP["10.100.50.69"]
	if !ok {
		t.Fatalf("missing 10.100.50.69")
	}
	if l1.Hostname != "wiz2c10a8" {
		t.Errorf("expected hostname wiz2c10a8, got %q", l1.Hostname)
	}
	if l1.MACAddr != "98:77:d5:2c:10:a8" {
		t.Errorf("expected lowercase mac, got %q", l1.MACAddr)
	}
	if l1.SubnetID != 50 {
		t.Errorf("expected subnet 50, got %d", l1.SubnetID)
	}

	l2, ok := byMAC["ee:41:6b:c8:f9:9d"]
	if !ok {
		t.Fatalf("missing by mac ee:41:6b:c8:f9:9d")
	}
	if l2.Hostname != "iphone" { // trailing dot stripped
		t.Errorf("expected hostname iphone without dot, got %q", l2.Hostname)
	}
}

func TestKeaCompanionFilesMerging(t *testing.T) {
	file1 := `address,hwaddr,client_id,valid_lifetime,expire,subnet_id,fqdn_fwd,fqdn_rev,hostname,state,user_context,pool_id
10.100.1.2,74:fe:ce:cb:4a:36,01:74:fe:ce:cb:4a:36,28800,1788761099,1,0,0,eap670,0,,0
`
	file2 := `address,hwaddr,client_id,valid_lifetime,expire,subnet_id,fqdn_fwd,fqdn_rev,hostname,state,user_context,pool_id
10.100.99.153,ee:41:6b:c8:f9:9d,01:ee:41:6b:c8:f9:9d,28800,1788764898,99,0,0,iphone,0,,0
`
	tmpDir := t.TempDir()
	basePath := filepath.Join(tmpDir, "dhcp4.leases")
	compPath := filepath.Join(tmpDir, "dhcp4.leases.2")

	if err := os.WriteFile(basePath, []byte(file1), 0644); err != nil {
		t.Fatalf("write file1: %v", err)
	}
	if err := os.WriteFile(compPath, []byte(file2), 0644); err != nil {
		t.Fatalf("write file2: %v", err)
	}

	reader := NewDHCPLeaseReader(basePath, "auto")
	leases, err := reader.GetLeases()
	if err != nil {
		t.Fatalf("GetLeases error: %v", err)
	}

	if len(leases) != 2 {
		t.Fatalf("expected 2 merged leases from base and companion, got %d", len(leases))
	}
}

func TestDnsmasqLeaseParser(t *testing.T) {
	dnsmasqData := `1788764898 00:11:22:33:44:55 10.100.1.50 my-pc 01:00:11:22:33:44:55
1788764899 66:77:88:99:aa:bb 10.100.1.51 * *
`
	tmpDir := t.TempDir()
	leasePath := filepath.Join(tmpDir, "dnsmasq.leases")
	if err := os.WriteFile(leasePath, []byte(dnsmasqData), 0644); err != nil {
		t.Fatalf("write dnsmasq file: %v", err)
	}

	reader := NewDHCPLeaseReader(leasePath, "dnsmasq")
	leases, err := reader.GetLeases()
	if err != nil {
		t.Fatalf("GetLeases error: %v", err)
	}

	if len(leases) != 2 {
		t.Fatalf("expected 2 leases, got %d", len(leases))
	}

	byIP, _, err := reader.GetLeasesMap()
	if err != nil {
		t.Fatalf("GetLeasesMap error: %v", err)
	}

	if byIP["10.100.1.50"].Hostname != "my-pc" {
		t.Errorf("expected hostname my-pc, got %q", byIP["10.100.1.50"].Hostname)
	}
	if byIP["10.100.1.51"].Hostname != "" {
		t.Errorf("expected empty hostname for *, got %q", byIP["10.100.1.51"].Hostname)
	}
}
