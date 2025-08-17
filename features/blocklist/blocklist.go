// File: features/blocklist/blocklist.go
package blocklist

import (
	log "github.com/ProxyFi/GoDNS"
	"time"
	"sync"
)

// Blocklist is the interface for different blocklist backends.
type Blocklist interface {
	IsBlocked(domain string) bool
	IsAllowed(domain string) bool
}

// Config holds the configuration for the blocklist module.
type Config struct {
	Enable          bool
	Backend         string
	File            string
	WhitelistFile   string
	RefreshInterval int
	RedisEnable     bool
	RedisKey        string
	RedisWhitelistKey string
	RedisSettings   interface{} // Use interface for flexibility
}

// block contains the logic for managing different blocklist backends.
type block struct {
	whitelist       sync.Map
	blacklist       sync.Map
	refreshInterval time.Duration
	fileBlocklist   *fileBlocklist
	redisBlocklist  *redisBlocklist
}

// NewBlocklist creates a new Blocklist instance based on the configuration.
func NewBlocklist(c *Config) Blocklist {
	if !c.Enable {
		return &block{}
	}

	b := &block{
		refreshInterval: time.Duration(c.RefreshInterval) * time.Second,
	}

	// Initialize file-based backend if enabled
	if c.Backend == "file" || c.File != "" || c.WhitelistFile != "" {
		b.fileBlocklist = NewFileBlocklist(c.File, c.WhitelistFile)
		b.fileBlocklist.Refresh()
		go func() {
			ticker := time.NewTicker(b.refreshInterval)
			defer ticker.Stop()
			for range ticker.C {
				log.Info("Refreshing file-based blocklist...")
				b.fileBlocklist.Refresh()
			}
		}()
	}

	// Initialize Redis-based backend if enabled
	if c.Backend == "redis" || c.RedisEnable {
		b.redisBlocklist = NewRedisBlocklist(c.RedisSettings, c.RedisKey, c.RedisWhitelistKey)
		b.redisBlocklist.Refresh()
		go func() {
			ticker := time.NewTicker(b.refreshInterval)
			defer ticker.Stop()
			for range ticker.C {
				log.Info("Refreshing Redis-based blocklist...")
				b.redisBlocklist.Refresh()
			}
		}()
	}

	return b
}

// IsBlocked checks if a domain is present in the blacklist.
func (b *block) IsBlocked(domain string) bool {
	if b.IsAllowed(domain) {
		return false
	}
	if b.fileBlocklist != nil && b.fileBlocklist.IsBlocked(domain) {
		return true
	}
	if b.redisBlocklist != nil && b.redisBlocklist.IsBlocked(domain) {
		return true
	}
	return false
}

// IsAllowed checks if a domain is present in the whitelist.
func (b *block) IsAllowed(domain string) bool {
	if b.fileBlocklist != nil && b.fileBlocklist.IsAllowed(domain) {
		return true
	}
	if b.redisBlocklist != nil && b.redisBlocklist.IsAllowed(domain) {
		return true
	}
	return false
}
