// File: dnssec/cache.go

package dnssec

import (
	"sync"
	"time"

	"github.com/miekg/dns"
)

// DNSSECCache provides a thread-safe in-memory cache for DNSSEC-related records,
// such as DS records and DNSKEYs, to improve validation performance.
// The cache entries have a time-to-live (TTL) and expire automatically.
type DNSSECCache struct {
	mu     sync.RWMutex
	dsData map[string]*dsData
}

// dsData is a record data structure for storing DNSKEY's hash.
// It also includes the original delegation DS and an optional chain.
type dsData struct {
	keyTag     uint16
	algorithm  uint8
	digestType uint8
	digest     []byte
	delegation *dns.DS
	chain      []*dns.DS
	expiration time.Time
}

// NewDNSSECCache creates a new DNSSECCache instance.
func NewDNSSECCache() *DNSSECCache {
	return &DNSSECCache{
		dsData: make(map[string]*dsData),
	}
}

// GetDS retrieves a DS record from the cache.
// It returns the dsData struct and a boolean indicating whether it was found.
// An expired entry will not be returned.
func (c *DNSSECCache) GetDS(name string) (*dsData, bool) {
	c.mu.RLock()
	data, ok := c.dsData[name]
	c.mu.RUnlock()

	if !ok || time.Now().After(data.expiration) {
		return nil, false
	}
	return data, true
}

// SetDS adds or updates a DS record in the cache.
// The expiration time is calculated based on the DS record's TTL.
func (c *DNSSECCache) SetDS(name string, data *dsData) {
	c.mu.Lock()
	defer c.mu.Unlock()
	
	// Default TTL for cache entry is 1 hour if not specified.
	ttl := time.Hour
	if data.delegation != nil && data.delegation.Header().Ttl > 0 {
		ttl = time.Duration(data.delegation.Header().Ttl) * time.Second
	}
	data.expiration = time.Now().Add(ttl)

	c.dsData[name] = data
}
