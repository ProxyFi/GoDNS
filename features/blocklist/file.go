package blocklist

import (
	"bufio"
	"os"
	"strings"
	"sync"
	"godns/internal/log"
)

// fileBlocklist manages the file-based block and allow lists.
type fileBlocklist struct {
	mu        sync.RWMutex
	blacklist map[string]struct{}
	whitelist map[string]struct{}
	blacklistFile string
	whitelistFile string
}

// NewFileBlocklist creates a new file-based blocklist instance.
func NewFileBlocklist(blacklistFile, whitelistFile string) *fileBlocklist {
	return &fileBlocklist{
		blacklist: make(map[string]struct{}),
		whitelist: make(map[string]struct{}),
		blacklistFile: blacklistFile,
		whitelistFile: whitelistFile,
	}
}

// Refresh reloads the blocklist and whitelist from their files.
func (f *fileBlocklist) Refresh() {
	f.mu.Lock()
	defer f.mu.Unlock()
	
	// Clear existing maps
	f.blacklist = make(map[string]struct{})
	f.whitelist = make(map[string]struct{})

	// Load blacklist
	if f.blacklistFile != "" {
		log.Debug("Loading blacklist from file: %s", f.blacklistFile)
		f.loadFromFile(f.blacklistFile, f.blacklist)
	}

	// Load whitelist
	if f.whitelistFile != "" {
		log.Debug("Loading whitelist from file: %s", f.whitelistFile)
		f.loadFromFile(f.whitelistFile, f.whitelist)
	}
}

// loadFromFile reads domains from a file and populates a map.
func (f *fileBlocklist) loadFromFile(filename string, domainMap map[string]struct{}) {
	file, err := os.Open(filename)
	if err != nil {
		log.Error("Failed to open blocklist file %s: %v", filename, err)
		return
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		domainMap[line] = struct{}{}
	}

	if err := scanner.Err(); err != nil {
		log.Error("Error reading blocklist file %s: %v", filename, err)
	}
	log.Info("Loaded %d domains from %s", len(domainMap), filename)
}

// IsBlocked checks if a domain is in the file-based blacklist.
func (f *fileBlocklist) IsBlocked(domain string) bool {
	f.mu.RLock()
	defer f.mu.RUnlock()
	_, ok := f.blacklist[domain]
	return ok
}

// IsAllowed checks if a domain is in the file-based whitelist.
func (f *fileBlocklist) IsAllowed(domain string) bool {
	f.mu.RLock()
	defer f.mu.RUnlock()
	_, ok := f.whitelist[domain]
	return ok
}
