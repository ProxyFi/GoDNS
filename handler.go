// File: handler.go

package godns

import (
	"time"
	"github.com/miekg/dns"
	"github.com/ProxyFi/GoDNS/features/blocklist"
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

// request represents a DNS query received by the server.
type request struct {
	net string
	w   dns.ResponseWriter
	req *dns.Msg
}

// GODNSHandler is the main DNS handler.
// It uses a goroutine pool to process incoming DNS requests.
type GODNSHandler struct {
	resolver  *Resolver
	cache, negCache Cache
	hosts     Hosts
	// blocklist holds the block and allow lists.
	blocklist blocklist.Blocklist
	// requestChan is a buffered channel that acts as a work queue for incoming requests.
	requestChan chan request
}

// NewHandler creates a new GODNSHandler instance and initializes its components.
// It now also initializes the goroutine worker pool.
func NewHandler() *GODNSHandler {

	var (
		cacheConfig CacheSettings
		resolver    *Resolver
		cache, negCache Cache
		err         error
	)

	resolver, err = NewResolver(settings.ResolvConfig)
	if err != nil {
		log.Error("Failed to create resolver: %s", err)
		panic(err)
	}

	cacheConfig = settings.Cache
	if cacheConfig.Backend == "memory" {
		cache = NewMemoryCache(cacheConfig.Expire, cacheConfig.Maxcount)
		negCache = NewMemoryCache(cacheConfig.Expire, cacheConfig.Maxcount)
	} else if cacheConfig.Backend == "redis" {
		cache = NewRedisCache(settings.Redis, cacheConfig.Expire)
		negCache = NewRedisCache(settings.Redis, cacheConfig.Expire)
	}

	h := &GODNSHandler{
		resolver:    resolver,
		cache:       cache,
		negCache:    negCache,
		hosts:       NewHosts(settings.Hosts, settings.Redis),
		blocklist:   blocklist.NewBlocklist(settings.Blocklist, settings.Redis),
		// requestChan is a buffered channel that acts as a queue for incoming requests.
		// The buffer size (e.g., 1000) should be tuned based on expected load.
		requestChan: make(chan request, 1000),
	}

	// Start a fixed number of worker goroutines to process requests from the channel.
	// The number of workers can be a configuration parameter.
	numWorkers := 100
	for i := 0; i < numWorkers; i++ {
		go h.worker()
	}

	return h
}

// worker is a goroutine that reads from the request channel and processes DNS queries.
func (h *GODNSHandler) worker() {
	// The worker runs indefinitely, processing requests from the queue.
	for req := range h.requestChan {
		h.handleRequest(req.net, req.w, req.req)
	}
}

// handleRequest processes a single DNS query. This logic was previously in DoTCP/DoUDP.
func (h *GODNSHandler) handleRequest(net string, w dns.ResponseWriter, req *dns.Msg) {
	// ... (The rest of the original logic from DoTCP/DoUDP is moved here) ...

	// --- Existing DoTCP/DoUDP logic starts here ---
	
	if req.MsgHdr.Response {
		return
	}
	
	q := req.Question[0]
	Q := Question{UnFqdn(q.Name), dns.Type(q.Qtype).String(), dns.Class(q.Qclass).String()}

	if h.blocklist.IsBlocked(Q.qname) {
		log.Debug("Blocked by blocklist: %s", Q.String())
		dns.HandleFailed(w, req)
		return
	}

	// Check hosts file
	if settings.Hosts.Enable {
		if ips, ok := h.hosts.Get(Q.qname); ok {
			mesg := new(dns.Msg)
			mesg.SetReply(req)
			mesg.Authoritative = true
			mesg.RecursionAvailable = true
			
			// Handle different query types
			if Q.qtype == "A" {
				var records []dns.RR
				for _, ipStr := range ips {
					ip := net.ParseIP(ipStr)
					if ip4 := ip.To4(); ip4 != nil {
						rr := new(dns.A)
						rr.Hdr = dns.RR_Header{Name: dns.Fqdn(Q.qname), Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: settings.Hosts.TTL}
						rr.A = ip4
						records = append(records, rr)
					}
				}
				mesg.Answer = records
			} else if Q.qtype == "AAAA" {
				var records []dns.RR
				for _, ipStr := range ips {
					ip := net.ParseIP(ipStr)
					if ip6 := ip.To16(); ip6 != nil && ip.To4() == nil {
						rr := new(dns.AAAA)
						rr.Hdr = dns.RR_Header{Name: dns.Fqdn(Q.qname), Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: settings.Hosts.TTL}
						rr.AAAA = ip6
						records = append(records, rr)
					}
				}
				mesg.Answer = records
			}

			w.WriteMsg(mesg)
			return
		}
	}
	
	key := KeyGen(Q)
	mesg, err := h.cache.Get(key)
	if err != nil {
		if mesg, err = h.negCache.Get(key); err != nil {
			log.Debug("%s didn't hit cache", Q.String())
		} else {
			log.Debug("%s hit negative cache", Q.String())
			dns.HandleFailed(w, req)
			return
		}
	} else {
		log.Debug("%s hit cache", Q.String())
		// we need this copy against concurrent modification of Id
		msg := *mesg
		msg.Id = req.Id
		w.WriteMsg(&msg)
		return
	}
	
	mesg, err = h.resolver.Lookup(net, req)

	if err != nil {
		log.Warn("Resolve query error %s", err)
		dns.HandleFailed(w, req)

		// cache the failure, too!
		if err = h.negCache.Set(key, nil); err != nil {
			log.Warn("Set %s negative cache failed: %v", Q.String(), err)
		}
		return
	}
	
	log.Debug("Cache RRs for %s", Q.String())
	if err = h.cache.Set(key, mesg); err != nil {
		log.Warn("Set %s cache failed: %v", Q.String(), err)
	}
	
	w.WriteMsg(mesg)
}

// DoTCP handles incoming TCP DNS requests. It pushes the request to the work queue.
func (h *GODNSHandler) DoTCP(w dns.ResponseWriter, req *dns.Msg) {
	// Push the request to the buffered channel. This call will be non-blocking
	// as long as the channel has capacity.
	h.requestChan <- request{net: "tcp", w: w, req: req}
}

// DoUDP handles incoming UDP DNS requests. It pushes the request to the work queue.
func (h *GODNSHandler) DoUDP(w dns.ResponseWriter, req *dns.Msg) {
	// Push the request to the buffered channel.
	h.requestChan <- request{net: "udp", w: w, req: req}
}
