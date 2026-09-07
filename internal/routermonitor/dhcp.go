package routermonitor

import (
	"bufio"
	"encoding/csv"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

// DHCPLease represents a single lease parsed from a DHCP server lease file.
type DHCPLease struct {
	IPAddr        string
	MACAddr       string
	Hostname      string
	ClientID      string
	ValidLifetime time.Duration
	Expire        time.Time
	SubnetID      int64
	State         int64
}

// DHCPLeaseReader reads DHCP leases from disk.
type DHCPLeaseReader interface {
	GetLeases() ([]DHCPLease, error)
	GetLeasesMap() (byIP map[string]DHCPLease, byMAC map[string]DHCPLease, err error)
}

// DHCPLeaseManager implements DHCPLeaseReader with support for Kea and dnsmasq.
type DHCPLeaseManager struct {
	filePath   string
	leaseType  string // "kea", "dnsmasq", or "auto"
	mu         sync.RWMutex
	lastModMap map[string]time.Time
	cached     []DHCPLease
}

// NewDHCPLeaseReader creates a new DHCPLeaseReader.
// If filePath is empty, it attempts to detect common default paths.
// If leaseType is empty, it defaults to "auto".
func NewDHCPLeaseReader(filePath string, leaseType string) *DHCPLeaseManager {
	if leaseType == "" {
		leaseType = "auto"
	}
	if filePath == "" {
		candidates := []string{
			"/var/lib/kea/dhcp4.leases",
			"/var/lib/kea/kea-leases4.csv",
			"/var/lib/misc/dnsmasq.leases",
			"/tmp/dhcp.leases",
		}
		for _, c := range candidates {
			if _, err := os.Stat(c); err == nil {
				filePath = c
				break
			}
		}
	}

	return &DHCPLeaseManager{
		filePath:   filePath,
		leaseType:  leaseType,
		lastModMap: make(map[string]time.Time),
	}
}

// GetLeases returns all active DHCP leases.
func (m *DHCPLeaseManager) GetLeases() ([]DHCPLease, error) {
	if m.filePath == "" {
		return nil, nil
	}

	files := m.findTargetFiles()
	if len(files) == 0 {
		return nil, nil
	}

	// Check if any file modified since last read
	m.mu.RLock()
	modified := false
	for _, f := range files {
		info, err := os.Stat(f)
		if err != nil {
			continue
		}
		if lastMod, ok := m.lastModMap[f]; !ok || info.ModTime().After(lastMod) {
			modified = true
			break
		}
	}
	if !modified && m.cached != nil {
		cached := m.cached
		m.mu.RUnlock()
		return cached, nil
	}
	m.mu.RUnlock()

	m.mu.Lock()
	defer m.mu.Unlock()

	newModMap := make(map[string]time.Time)
	var allLeases []DHCPLease

	for _, f := range files {
		info, err := os.Stat(f)
		if err != nil {
			continue
		}
		newModMap[f] = info.ModTime()

		leases, err := m.parseFile(f)
		if err != nil {
			log.Printf("warn: failed parsing dhcp lease file %s: %v", f, err)
			continue
		}
		allLeases = append(allLeases, leases...)
	}

	// Deduplicate by IP: later expire timestamp wins
	mergedByIP := make(map[string]DHCPLease)
	for _, l := range allLeases {
		if existing, ok := mergedByIP[l.IPAddr]; ok {
			if l.Expire.After(existing.Expire) {
				mergedByIP[l.IPAddr] = l
			}
		} else {
			mergedByIP[l.IPAddr] = l
		}
	}

	deduped := make([]DHCPLease, 0, len(mergedByIP))
	for _, l := range mergedByIP {
		deduped = append(deduped, l)
	}

	m.lastModMap = newModMap
	m.cached = deduped
	return deduped, nil
}

// GetLeasesMap returns active leases indexed by IP and normalized MAC.
func (m *DHCPLeaseManager) GetLeasesMap() (map[string]DHCPLease, map[string]DHCPLease, error) {
	leases, err := m.GetLeases()
	if err != nil {
		return nil, nil, err
	}

	byIP := make(map[string]DHCPLease, len(leases))
	byMAC := make(map[string]DHCPLease, len(leases))

	for _, l := range leases {
		if l.IPAddr != "" {
			byIP[l.IPAddr] = l
		}
		if l.MACAddr != "" {
			byMAC[strings.ToLower(l.MACAddr)] = l
		}
	}

	return byIP, byMAC, nil
}

// findTargetFiles finds the lease file and any companion files (e.g. dhcp4.leases.2 for Kea Memfile LFC).
func (m *DHCPLeaseManager) findTargetFiles() []string {
	if m.filePath == "" {
		return nil
	}

	base := filepath.Clean(m.filePath)
	dir := filepath.Dir(base)
	prefix := filepath.Base(base)

	entries, err := os.ReadDir(dir)
	if err != nil {
		if _, statErr := os.Stat(base); statErr == nil {
			return []string{base}
		}
		return nil
	}

	var files []string
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if (name == prefix || strings.HasPrefix(name, prefix+".")) && !strings.HasSuffix(name, ".lock") && !strings.HasSuffix(name, ".tmp") {
			files = append(files, filepath.Join(dir, name))
		}
	}

	if len(files) == 0 {
		if _, statErr := os.Stat(base); statErr == nil {
			return []string{base}
		}
	}

	return files
}

func (m *DHCPLeaseManager) parseFile(path string) ([]DHCPLease, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	t := m.leaseType
	if t == "auto" {
		t = detectLeaseType(f)
		if _, err := f.Seek(0, io.SeekStart); err != nil {
			return nil, fmt.Errorf("seek start: %w", err)
		}
	}

	switch t {
	case "kea":
		return parseKeaCSV(f)
	case "dnsmasq":
		return parseDnsmasqLeases(f)
	default:
		return parseKeaCSV(f)
	}
}

func detectLeaseType(r io.Reader) string {
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.Contains(line, "address") && strings.Contains(line, "hwaddr") {
			return "kea"
		}
		if strings.Contains(line, ",") {
			return "kea"
		}
		fields := strings.Fields(line)
		if len(fields) >= 4 {
			if _, err := strconv.ParseInt(fields[0], 10, 64); err == nil {
				return "dnsmasq"
			}
		}
		break
	}
	return "kea"
}

// parseKeaCSV parses Kea DHCP4 CSV memfile format.
func parseKeaCSV(r io.Reader) ([]DHCPLease, error) {
	reader := csv.NewReader(r)
	reader.FieldsPerRecord = -1
	reader.TrimLeadingSpace = true

	headers, err := reader.Read()
	if err != nil {
		return nil, err
	}

	colIdx := make(map[string]int)
	for i, h := range headers {
		colIdx[strings.ToLower(strings.TrimSpace(h))] = i
	}

	addrIdx, hasAddr := colIdx["address"]
	hwIdx, hasHW := colIdx["hwaddr"]
	if !hasAddr || !hasHW {
		return nil, fmt.Errorf("missing address or hwaddr column in Kea CSV header")
	}

	hostIdx, hasHost := colIdx["hostname"]
	clientIdx, hasClient := colIdx["client_id"]
	validIdx, hasValid := colIdx["valid_lifetime"]
	expireIdx, hasExpire := colIdx["expire"]
	subnetIdx, hasSubnet := colIdx["subnet_id"]
	stateIdx, hasState := colIdx["state"]

	now := time.Now()
	var leases []DHCPLease

	for {
		rec, err := reader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			continue
		}

		if len(rec) <= addrIdx || len(rec) <= hwIdx {
			continue
		}

		ipStr := strings.TrimSpace(rec[addrIdx])
		if net.ParseIP(ipStr) == nil {
			continue
		}

		hwStr := strings.ToLower(strings.TrimSpace(rec[hwIdx]))

		var state int64
		if hasState && len(rec) > stateIdx {
			s, err := strconv.ParseInt(strings.TrimSpace(rec[stateIdx]), 10, 64)
			if err == nil {
				state = s
			}
		}
		if state == 1 || state == 2 {
			continue
		}

		var expireTime time.Time
		if hasExpire && len(rec) > expireIdx {
			expUnix, err := strconv.ParseInt(strings.TrimSpace(rec[expireIdx]), 10, 64)
			if err == nil && expUnix > 0 {
				expireTime = time.Unix(expUnix, 0)
				if expireTime.Before(now.Add(-10 * time.Minute)) {
					continue
				}
			}
		}

		var hostname string
		if hasHost && len(rec) > hostIdx {
			hostname = strings.TrimSpace(rec[hostIdx])
			hostname = strings.TrimSuffix(hostname, ".")
		}

		var clientID string
		if hasClient && len(rec) > clientIdx {
			clientID = strings.TrimSpace(rec[clientIdx])
		}

		var lifetime time.Duration
		if hasValid && len(rec) > validIdx {
			ltSec, err := strconv.ParseInt(strings.TrimSpace(rec[validIdx]), 10, 64)
			if err == nil && ltSec > 0 {
				lifetime = time.Duration(ltSec) * time.Second
			}
		}

		var subnetID int64
		if hasSubnet && len(rec) > subnetIdx {
			sub, err := strconv.ParseInt(strings.TrimSpace(rec[subnetIdx]), 10, 64)
			if err == nil {
				subnetID = sub
			}
		}

		leases = append(leases, DHCPLease{
			IPAddr:        ipStr,
			MACAddr:       hwStr,
			Hostname:      hostname,
			ClientID:      clientID,
			ValidLifetime: lifetime,
			Expire:        expireTime,
			SubnetID:      subnetID,
			State:         state,
		})
	}

	return leases, nil
}

// parseDnsmasqLeases parses dnsmasq lease format:
// <expire_unix> <mac> <ip> <hostname> <client_id>
func parseDnsmasqLeases(r io.Reader) ([]DHCPLease, error) {
	scanner := bufio.NewScanner(r)
	var leases []DHCPLease
	now := time.Now()

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}

		expUnix, err := strconv.ParseInt(fields[0], 10, 64)
		if err != nil {
			continue
		}
		var expireTime time.Time
		if expUnix > 0 {
			expireTime = time.Unix(expUnix, 0)
			if expireTime.Before(now.Add(-10 * time.Minute)) {
				continue
			}
		}

		hwStr := strings.ToLower(fields[1])
		ipStr := fields[2]
		if net.ParseIP(ipStr) == nil {
			continue
		}

		hostname := fields[3]
		if hostname == "*" {
			hostname = ""
		} else {
			hostname = strings.TrimSuffix(hostname, ".")
		}

		clientID := ""
		if len(fields) >= 5 && fields[4] != "*" {
			clientID = fields[4]
		}

		leases = append(leases, DHCPLease{
			IPAddr:   ipStr,
			MACAddr:  hwStr,
			Hostname: hostname,
			ClientID: clientID,
			Expire:   expireTime,
			State:    0,
		})
	}

	return leases, scanner.Err()
}
