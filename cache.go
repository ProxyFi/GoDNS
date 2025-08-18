package godns

import (
	"context"
	"crypto/md5"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/bradfitz/gomemcache/memcache"
	"github.com/redis/go-redis/v9"
	"github.com/miekg/dns"
)

// KeyNotFound is an error type for when a key does not exist in the cache.
type KeyNotFound struct {
	key string
}

func (e KeyNotFound) Error() string {
	return fmt.Sprintf("key %q not found", e.key)
}

// KeyExpired is an error type for when a key exists but has expired.
type KeyExpired struct {
	Key string
}

func (e KeyExpired) Error() string {
	return fmt.Sprintf("key %q expired", e.Key)
}

// CacheIsFull is an error type indicating the cache has reached its maximum capacity.
type CacheIsFull struct{}

func (e CacheIsFull) Error() string {
	return "cache is full"
}

// SerializerError is an error type for issues with message serialization.
type SerializerError struct {
	err error
}

func (e SerializerError) Error() string {
	return fmt.Sprintf("serializer error: %v", e.err)
}

// Mesg wraps a dns.Msg with its expiration time.
type Mesg struct {
	Msg    *dns.Msg
	Expire time.Time
}

// Cache defines the interface for different caching backends.
type Cache interface {
	Get(key string) (Msg *dns.Msg, err error)
	Set(key string, Msg *dns.Msg) error
	Exists(key string) bool
	Remove(key string) error
	Full() bool
}

// MemoryCache is a simple in-memory cache implementation.
type MemoryCache struct {
	Backend  map[string]Mesg
	Expire   time.Duration
	Maxcount int
	mu       sync.RWMutex
}

// Get retrieves a DNS message from the in-memory cache by key.
func (c *MemoryCache) Get(key string) (*dns.Msg, error) {
	c.mu.RLock()
	mesg, ok := c.Backend[key]
	c.mu.RUnlock()
	if !ok {
		return nil, KeyNotFound{key}
	}

	if mesg.Expire.Before(time.Now()) {
		c.Remove(key)
		return nil, KeyExpired{key}
	}

	return mesg.Msg, nil
}

// Set stores a DNS message in the in-memory cache.
func (c *MemoryCache) Set(key string, msg *dns.Msg) error {
	if c.Full() && !c.Exists(key) {
		return CacheIsFull{}
	}

	expire := time.Now().Add(c.Expire)
	mesg := Mesg{msg, expire}
	c.mu.Lock()
	c.Backend[key] = mesg
	c.mu.Unlock()
	return nil
}

// Remove deletes a DNS message from the in-memory cache.
func (c *MemoryCache) Remove(key string) error {
	c.mu.Lock()
	delete(c.Backend, key)
	c.mu.Unlock()
	return nil
}

// Exists checks if a key is present in the in-memory cache.
func (c *MemoryCache) Exists(key string) bool {
	c.mu.RLock()
	_, ok := c.Backend[key]
	c.mu.RUnlock()
	return ok
}

// Length returns the number of items in the cache.
func (c *MemoryCache) Length() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.Backend)
}

// Full checks if the in-memory cache has reached its maximum capacity.
func (c *MemoryCache) Full() bool {
	// If Maxcount is zero, the cache is never full.
	if c.Maxcount == 0 {
		return false
	}
	return c.Length() >= c.Maxcount
}

// NewMemcachedCache creates a new MemcachedCache instance.
func NewMemcachedCache(servers []string, expire int32) *MemcachedCache {
	c := memcache.New(servers...)
	return &MemcachedCache{
		backend: c,
		expire:  expire,
	}
}

// MemcachedCache is a cache implementation using Memcached as the backend.
type MemcachedCache struct {
	backend *memcache.Client
	expire  int32
}

// Set stores a DNS message in Memcached.
func (m *MemcachedCache) Set(key string, msg *dns.Msg) error {
	var val []byte
	var err error

	if msg == nil {
		val = []byte("nil")
	} else {
		val, err = msg.Pack()
	}
	if err != nil {
		return SerializerError{err}
	}
	return m.backend.Set(&memcache.Item{Key: key, Value: val, Expiration: m.expire})
}

// Get retrieves a DNS message from Memcached.
func (m *MemcachedCache) Get(key string) (*dns.Msg, error) {
	var msg dns.Msg
	item, err := m.backend.Get(key)
	if err != nil {
		return &msg, KeyNotFound{key}
	}
	err = msg.Unpack(item.Value)
	if err != nil {
		return &msg, SerializerError{err}
	}
	return &msg, err
}

// Exists checks if a key is present in Memcached.
func (m *MemcachedCache) Exists(key string) bool {
	_, err := m.backend.Get(key)
	return err == nil
}

// Remove deletes a key from Memcached.
func (m *MemcachedCache) Remove(key string) error {
	return m.backend.Delete(key)
}

// Full indicates whether the cache is at capacity. Memcached is
// an LRU cache, so it is never "full" in this context.
func (m *MemcachedCache) Full() bool {
	return false
}

// NewRedisCache creates a new RedisCache instance.
func NewRedisCache(rs RedisSettings, expire int64) *RedisCache {
	rdb := redis.NewClient(&redis.Options{
		Addr:     rs.Addr, // Corrected: Used the existing Addr field
		DB:       rs.DB,
		Password: rs.Password,
	})
	return &RedisCache{
		Backend: rdb,
		Expire:  time.Duration(expire) * time.Second,
	}
}

// RedisCache is a cache implementation using Redis as the backend.
type RedisCache struct {
	Backend *redis.Client
	Expire  time.Duration
}

// Get retrieves a DNS message from Redis.
func (r *RedisCache) Get(key string) (*dns.Msg, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	item, err := r.Backend.Get(ctx, key).Bytes()
	if err == redis.Nil {
		return nil, KeyNotFound{key}
	}
	if err != nil {
		return nil, err
	}

	var msg dns.Msg
	if string(item) == "nil" {
		// Handle nil values for negacache
		return nil, nil
	}
	err = msg.Unpack(item)
	if err != nil {
		return &msg, SerializerError{err}
	}
	return &msg, err
}

// Set stores a DNS message in Redis with a specified expiration time.
func (r *RedisCache) Set(key string, msg *dns.Msg) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var val []byte
	var err error

	if msg == nil {
		val = []byte("nil")
	} else {
		val, err = msg.Pack()
	}
	if err != nil {
		return SerializerError{err}
	}

	return r.Backend.Set(ctx, key, val, r.Expire).Err()
}

// Exists checks if a key is present in Redis.
func (r *RedisCache) Exists(key string) bool {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	
	val, err := r.Backend.Exists(ctx, key).Result()
	return err == nil && val > 0
}

// Remove deletes a key from Redis.
func (r *RedisCache) Remove(key string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := r.Backend.Del(ctx, key).Result()
	return err
}

// Full indicates whether the cache is at capacity. Redis is not "full"
// in this context as it can scale.
func (r *RedisCache) Full() bool {
	return false
}

// KeyGen generates a unique key for a DNS question using MD5 hashing.
func KeyGen(q Question) string {
	h := md5.New()
	h.Write([]byte(q.String()))
	x := h.Sum(nil)
	key := fmt.Sprintf("%x", x)
	return key
}

// JsonSerializer provides methods for marshaling and unmarshaling
// DNS messages to and from JSON format.
type JsonSerializer struct{}

// Dumps serializes a dns.Msg to a JSON byte slice.
func (*JsonSerializer) Dumps(mesg *dns.Msg) (encoded []byte, err error) {
	encoded, err = json.Marshal(*mesg)
	return
}

// Loads deserializes a JSON byte slice into a dns.Msg.
func (*JsonSerializer) Loads(data []byte) (*dns.Msg, error) {
	var mesg dns.Msg
	err := json.Unmarshal(data, &mesg)
	return &mesg, err
}
