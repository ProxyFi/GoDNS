package godns

import (
	"bufio"
	"context"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/ProxyFi/GoDNS/internal/log"
)

// Hosts manages host records from a local file and a remote Redis instance.
// It prioritizes the local hosts file over Redis.
type Hosts struct {
	fileHosts       *FileHosts
	redisHosts      *RedisHosts
	refreshInterval time.Duration
}

// NewHosts creates a new Hosts instance. It initializes FileHosts and RedisHosts
// based on the provided settings and starts a background goroutine to refresh
// the host records at a regular interval.
func NewHosts(hs HostsSettings, rs RedisSettings) Hosts {
	fileHosts := &FileHosts{
		file:  hs.HostsFile,
		hosts: make(map[string]string),
	}

	var redisHosts *RedisHosts
	if hs.RedisEnable {
		rdb := redis.NewClient(&redis.Options{
			Addr:     rs.Addr, // Corrected: Used the existing Addr field
			DB:       rs.DB,
			Password: rs.Password,
		})
		redisHosts = &RedisHosts{
			redis: rdb,
			key:   hs.RedisKey,
			hosts: make(map[string]string),
		}
	}

	hosts := Hosts{fileHosts, redisHosts, time.Second * time.Duration(hs.RefreshInterval)}
	hosts.refresh()
	return hosts
}

// Get attempts to find the IP address(es) for a given domain.
// It first checks the local hosts file, and if not found, it then checks Redis.
// The `family` parameter specifies whether to look for IPv4 or IPv6 addresses.
// It returns a slice of net.IP and a boolean indicating if a match was found.
func (h *Hosts) Get(domain string, family int) ([]net.IP, bool) {
	var sips []string
	var ip net.IP
	var ips []net.IP
	var ok bool

	// Match local /etc/hosts file first.
	sips, ok = h.fileHosts.Get(domain)
	if !ok {
		// If not found, match remote redis records second.
		if h.redisHosts != nil {
			sips, ok = h.redisHosts.Get(domain)
		}
	}

	if !ok || sips == nil {
		return nil, false
	}

	for _, sip := range sips {
		parsedIP := net.ParseIP(sip)
		if parsedIP == nil {
			continue
		}

		switch family {
		case _IP4Query:
			ip = parsedIP.To4()
		case _IP6Query:
			ip = parsedIP.To16()
		default:
			continue
		}

		if ip != nil {
			ips = append(ips, ip)
		}
	}

	return ips, (ips != nil)
}

// refresh starts a background goroutine to update host records from the
// local file and Redis at a fixed interval.
func (h *Hosts) refresh() {
	ticker := time.NewTicker(h.refreshInterval)
	go func() {
		for {
			h.fileHosts.Refresh()
			if h.redisHosts != nil {
				h.redisHosts.Refresh()
			}
			<-ticker.C
		}
	}()
}

// RedisHosts manages host records stored in a Redis hash.
type RedisHosts struct {
	redis *redis.Client
	key   string
	hosts map[string]string
	mu    sync.RWMutex
}

// Get retrieves the IP address(es) for a given domain from the Redis-backed cache.
// It supports exact domain matching and wildcard matching for subdomains.
func (r *RedisHosts) Get(domain string) ([]string, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	domain = strings.ToLower(domain)
	ip, ok := r.hosts[domain]
	if ok {
		return strings.Split(ip, ","), true
	}

	// Support wildcard domains like "*.example.com"
	for host, ip := range r.hosts {
		if strings.HasPrefix(host, "*.") {
			if strings.HasSuffix(domain, strings.TrimPrefix(host, "*")) {
				return strings.Split(ip, ","), true
			}
		}
	}
	return nil, false
}

// Set adds or updates a host record in the Redis hash.
func (r *RedisHosts) Set(domain, ip string) (bool, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	
	r.mu.Lock()
	defer r.mu.Unlock()
	
	cmd := r.redis.HSet(ctx, r.key, strings.ToLower(domain), ip)
	return cmd.Val() > 0, cmd.Err()
}

// Refresh updates the in-memory cache of host records by fetching all
// key-value pairs from the Redis hash.
func (r *RedisHosts) Refresh() {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	r.mu.Lock()
	defer r.mu.Unlock()
	r.clear()

	result, err := r.redis.HGetAll(ctx, r.key).Result()
	if err != nil {
		log.Warn("Update hosts records from redis failed: %s", err)
	} else {
		for host, ip := range result {
			r.hosts[host] = ip
		}
		log.Debug("Updated hosts records from redis. Total %d records.", len(r.hosts))
	}
}

// clear empties the in-memory map of host records.
func (r *RedisHosts) clear() {
	r.hosts = make(map[string]string)
}

// FileHosts manages host records from a local file, like `/etc/hosts`.
type FileHosts struct {
	file  string
	hosts map[string]string
	mu    sync.RWMutex
}

// Get retrieves the IP address(es) for a given domain from the local file cache.
// It supports exact domain matching and wildcard matching.
func (f *FileHosts) Get(domain string) ([]string, bool) {
	f.mu.RLock()
	defer f.mu.RUnlock()
	domain = strings.ToLower(domain)
	ip, ok := f.hosts[domain]
	if ok {
		return []string{ip}, true
	}

	// Support wildcard domains like "*.example.com"
	for host, ip := range f.hosts {
		if strings.HasPrefix(host, "*.") {
			if strings.HasSuffix(domain, strings.TrimPrefix(host, "*")) {
				return []string{ip}, true
			}
		}
	}

	return nil, false
}

// Refresh reads and parses the host file, updating the in-memory cache.
func (f *FileHosts) Refresh() {
	buf, err := os.Open(f.file)
	if err != nil {
		log.Warn("Update hosts records from file failed: %s", err)
		return
	}
	defer buf.Close()

	f.mu.Lock()
	defer f.mu.Unlock()

	f.clear()

	scanner := bufio.NewScanner(buf)
	for scanner.Scan() {
		line := scanner.Text()
		line = strings.TrimSpace(line)
		line = strings.ReplaceAll(line, "\t", " ")

		if strings.HasPrefix(line, "#") || line == "" {
			continue
		}

		parts := strings.Split(line, " ")

		if len(parts) < 2 {
			continue
		}

		ip := parts[0]
		if !isIP(ip) {
			continue
		}

		// The rest of the line contains one or more domains.
		for i := 1; i < len(parts); i++ {
			domain := strings.TrimSpace(parts[i])
			if domain == "" {
				continue
			}
			f.hosts[strings.ToLower(domain)] = ip
		}
	}
	log.Debug("Updated hosts records from %s. Total %d records.", f.file, len(f.hosts))
}

// clear empties the in-memory map of host records.
func (f *FileHosts) clear() {
	f.hosts = make(map[string]string)
}
