// File: dnssec/trust_anchor.go

package dnssec

import (
	"fmt"

	"github.com/miekg/dns"
	"github.com/ProxyFi/GoDNS/internal/log"
)

// TrustAnchorManager manages the set of trusted DNSKEYs.
// It provides methods for adding, retrieving, and loading trust anchors.
type TrustAnchorManager struct {
	anchors map[uint16]*dns.DNSKEY
}

// NewTrustAnchorManager creates a new TrustAnchorManager.
func NewTrustAnchorManager() *TrustAnchorManager {
	return &TrustAnchorManager{
		anchors: make(map[uint16]*dns.DNSKEY),
	}
}

// Add adds a DNSKEY as a new trust anchor.
// The key tag is used as the primary identifier.
func (m *TrustAnchorManager) Add(dnskey *dns.DNSKEY) {
	keyTag := dnskey.KeyTag()
	m.anchors[keyTag] = dnskey
	log.Info("Added new trust anchor with key tag: ", keyTag)
}

// Get retrieves a DNSKEY from the trust store by its key tag.
func (m *TrustAnchorManager) Get(keyTag uint16) (*dns.DNSKEY, bool) {
	anchor, ok := m.anchors[keyTag]
	return anchor, ok
}

// LoadFromFile loads a set of trust anchors from a file.
// The file should be in a format like BIND's `bind.keys`.
func (m *TrustAnchorManager) LoadFromFile(path string) error {
	// This is a placeholder for a real file parser.
	// You would use a library or a custom parser to read the file
	// and add the DNSKEYs.
	log.Warn("LoadFromFile is not implemented. Please load keys manually.")
	return fmt.Errorf("LoadFromFile not yet implemented")
}
