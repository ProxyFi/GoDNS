package blocklist

import (
	"context"
	"strings"
	"sync"
	"time"

	"github.com/go-redis/redis/v9"
	"github.com/ProxyFi/GoDNS/internal/log"
)

// redisBlocklist manages the Redis-based block and allow lists.
type redisBlocklist struct {
	mu        sync.RWMutex
	blacklist map[string]struct{}
	whitelist map[string]struct{}
	client    *redis.Client
	blacklistKey string
	whitelistKey string
}

// NewRedisBlocklist creates a new Redis-based blocklist instance.
func NewRedisBlocklist(redisSettings interface{}, blacklistKey, whitelistKey string) *redisBlocklist {
	rs, ok := redisSettings.(map[string]interface{})
	if !ok {
		log.Error("Invalid Redis settings configuration for blocklist")
		return nil
	}

	client := redis.NewClient(&redis.Options{
		Addr:     rs["host"].(string) + ":" + rs["port"].(string),
		Password: rs["password"].(string),
		DB:       int(rs["db"].(int64)),
	})

	return &redisBlocklist{
		blacklist:    make(map[string]struct{}),
		whitelist:    make(map[string]struct{}),
		client:       client,
		blacklistKey: blacklistKey,
		whitelistKey: whitelistKey,
	}
}

// Refresh reloads the blocklist and whitelist from Redis.
func (r *redisBlocklist) Refresh() {
	r.mu.Lock()
	defer r.mu.Unlock()

	// Clear existing maps
	r.blacklist = make(map[string]struct{})
	r.whitelist = make(map[string]struct{})

	// Load blacklist from Redis
	if r.blacklistKey != "" {
		log.Debug("Loading blacklist from Redis key: %s", r.blacklistKey)
		r.loadFromRedis(r.blacklistKey, r.blacklist)
	}

	// Load whitelist from Redis
	if r.whitelistKey != "" {
		log.Debug("Loading whitelist from Redis key: %s", r.whitelistKey)
		r.loadFromRedis(r.whitelistKey, r.whitelist)
	}
}

// loadFromRedis fetches domains from a Redis set and populates a map.
func (r *redisBlocklist) loadFromRedis(key string, domainMap map[string]struct{}) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	members, err := r.client.SMembers(ctx, key).Result()
	if err != nil {
		log.Error("Failed to load domains from Redis key %s: %v", key, err)
		return
	}

	for _, domain := range members {
		domainMap[strings.ToLower(domain)] = struct{}{}
	}
	log.Info("Loaded %d domains from Redis key %s", len(domainMap), key)
}

// IsBlocked checks if a domain is in the Redis-based blacklist.
func (r *redisBlocklist) IsBlocked(domain string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	_, ok := r.blacklist[domain]
	return ok
}

// IsAllowed checks if a domain is in the Redis-based whitelist.
func (r *redisBlocklist) IsAllowed(domain string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	_, ok := r.whitelist[domain]
	return ok
}

