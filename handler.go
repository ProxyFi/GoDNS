// File: handler.go
package godns

import (
	"time"

	"github.com/miekg/dns"
	"github.com/ProxyFi/GoDNS/features/blocklist"
	"github.com/ProxyFi/GoDNS/features/dnssec"
	"github.com/ProxyFi/GoDNS/internal/log"
)

const (
	notIPQuery = 0
	_IP4Query  = 4
	_IP6Query  = 6
)

// Question represents a DNS query question.
type Question struct {
	qname  string
	qtype  string
	qclass string
}

// String returns a string representation of the Question.
func (q *Question) String() string {
	return q.qname + " " + q.qclass + " " + q.qtype
}

// GODNSHandler is the main DNS handler.
type GODNSHandler struct {
	resolver  *Resolver
	cache, negCache Cache
	hosts     Hosts
	// blocklist holds the block and allow lists.
	blocklist blocklist.Blocklist
	// dnssec holds the DNSSEC validation logic.
	dnssec *dnssec.DNSSEC
}

// NewHandler creates a new GODNSHandler instance and initializes its components.
func NewHandler() *GODNSHandler {

	var (
		cacheConfig CacheSettings
		resolver    *Resolver
		cache, negCache Cache
	)

	// Initialize resolver
	resolver = NewResolver(settings.ResolvConfig)

	// Initialize cache and negative cache
	cacheConfig = settings.Cache
	switch cacheConfig.Backend {
	case "memory":
		cache = &MemoryCache{
			Backend: make(map[string]Mesg, cacheConfig.Maxcount),
			Expire:  time.Duration(cacheConfig.Expire) * time.Second,
			lock:    new(sync.RWMutex),
		}
		negCache = &MemoryCache{
			Backend: make(map[string]Mesg, cacheConfig.Maxcount),
			Expire:  time.Duration(cacheConfig.Expire) * time.Second,
			lock:    new(sync.RWMutex),
		}
	default:
		// fall back to memory cache
		cache = &MemoryCache{
			Backend: make(map[string]Mesg, cacheConfig.Maxcount),
			Expire:  time.Duration(cacheConfig.Expire) * time.Second,
			lock:    new(sync.RWMutex),
		}
		negCache = &MemoryCache{
			Backend: make(map[string]Mesg, cacheConfig.Maxcount),
			Expire:  time.Duration(cacheConfig.Expire) * time.Second,
			lock:    new(sync.RWMutex),
		}
	}

	// Initialize hosts
	hosts := NewHosts(settings.Hosts, settings.Redis)

	// Initialize blocklist
	blocklist := blocklist.NewBlocklist(settings.Blocklist, settings.Redis)

	var dnssecInstance *dnssec.DNSSEC
	if settings.DNSSEC.Enable {
		dnssecInstance = dnssec.NewDNSSEC(settings.DNSSEC)
	}

	return &GODNSHandler{resolver: resolver, cache: cache, negCache: negCache, hosts: hosts, blocklist: blocklist, dnssec: dnssecInstance}
}

// DoTCP handles DNS requests over TCP.
func (h *GODNSHandler) DoTCP(w dns.ResponseWriter, req *dns.Msg) {
	h.serveDNS(w, req)
}

// DoUDP handles DNS requests over UDP.
func (h *GODNSHandler) DoUDP(w dns.ResponseWriter, req *dns.Msg) {
	h.serveDNS(w, req)
}

func (h *GODNSHandler) serveDNS(w dns.ResponseWriter, req *dns.Msg) {
	// Check if the query name is a blocklist domain.
	if settings.Blocklist.Enable && h.blocklist.IsBlocked(req.Question[0].Name) {
		dns.HandleFailed(w, req)
		return
	}

	q := req.Question[0]
	Q := Question{UnFqdn(q.Name), dns.Type(q.Qtype).String(), dns.Class(q.Qclass).String()}

	log.Debug("Query %s", Q.String())

	// Check hosts file first.
	// Hosts file record has a higher priority than DNSSEC validation.
	// If a record is found in the hosts file, we return it immediately.
	if settings.Hosts.Enable {
		if ips, ok := h.hosts.Get(Q.qname); ok {
			m := new(dns.Msg)
			m.SetReply(req)
			m.Authoritative = true
			if settings.ResolvConfig.SetEDNS0 {
				m.SetEdns0(4096, false)
			}

			if q.Qtype == dns.TypeA {
				for _, ip := range ips {
					if isIPv4(ip) {
						rr := new(dns.A)
						rr.Hdr = dns.RR_Header{Name: dns.Fqdn(Q.qname), Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: settings.Hosts.TTL}
						rr.A = net.ParseIP(ip).To4()
						m.Answer = append(m.Answer, rr)
					}
				}
			} else if q.Qtype == dns.TypeAAAA {
				for _, ip := range ips {
					if isIPv6(ip) {
						rr := new(dns.AAAA)
						rr.Hdr = dns.RR_Header{Name: dns.Fqdn(Q.qname), Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: settings.Hosts.TTL}
						rr.AAAA = net.ParseIP(ip).To16()
						m.Answer = append(m.Answer, rr)
					}
				}
			}

			w.WriteMsg(m)
			return
		}
	}

	// Check cache first.
	key := KeyGen(Q)
	mesg, err := h.cache.Get(key)
	if err != nil {
		// Cache miss. Check negative cache.
		if mesg, err = h.negCache.Get(key); err != nil {
			log.Debug("%s didn't hit cache", Q.String())
		} else {
			// Hit negative cache, so we know this query failed recently.
			// Return a server failure message immediately.
			log.Debug("%s hit negative cache", Q.String())
			dns.HandleFailed(w, req)
			return
		}
	} else {
		// Cache hit.
		log.Debug("%s hit cache", Q.String())
		// We need this copy against concurrent modification of Id.
		msg := *mesg
		msg.Id = req.Id

		// If DNSSEC is enabled and the query has the DO bit, we will set the AD bit.
		if settings.DNSSEC.Enable && h.isDNSSECQuery(req) {
			msg.AuthenticatedData = true
		}

		w.WriteMsg(&msg)
		return
	}

	// Resolve the query with the upstream server.
	mesg, err = h.resolver.Lookup(w.RemoteAddr().Network(), req, h.dnssec)
	if err != nil {
		log.Warn("Resolve query error %s", err)
		dns.HandleFailed(w, req)

		// Cache the failure, too!
		if err = h.negCache.Set(key, nil); err != nil {
			log.Warn("Set %s negative cache failed: %v", Q.String(), err)
		}
		return
	}

	// Set the AD bit for DNSSEC responses if the query has the DO bit.
	if settings.DNSSEC.Enable && h.isDNSSECQuery(req) {
		mesg.AuthenticatedData = true
	}

	w.WriteMsg(mesg)

	// Cache the response.
	if err = h.cache.Set(key, mesg); err != nil {
		log.Warn("Set %s cache failed: %v", Q.String(), err)
	}
}

// isDNSSECQuery checks if the incoming request has the DNSSEC OK (DO) bit set.
func (h *GODNSHandler) isDNSSECQuery(req *dns.Msg) bool {
	if req.IsEdns0() != nil {
		// Check for the DO bit in the EDNS0 OPT record.
		// The DO bit is represented by dns.Do, which is a bit flag in the EDNS0 record's flags.
		return req.Extra[0].(*dns.OPT).Do()
	}
	return false
}

// isIPv4 checks if a string is a valid IPv4 address.
func isIPv4(s string) bool {
	return net.ParseIP(s).To4() != nil
}

// isIPv6 checks if a string is a valid IPv6 address.
func isIPv6(s string) bool {
	return net.ParseIP(s).To16() != nil
}
