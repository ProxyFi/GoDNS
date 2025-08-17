package godns

import (
	"net"
	"time"
	
	"github.com/miekg/dns"
	
	"github.com/ProxyFi/GoDNS/features/blocklist"
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
	resolver        *Resolver
	cache, negCache Cache
	hosts           Hosts
	// blocklist holds the block and allow lists.
	blocklist       blocklist.Blocklist
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
			Backend:  make(map[string]Mesg, cacheConfig.Maxcount),
			Expire:   time.Duration(cacheConfig.Expire) * time.Second,
			Maxcount: cacheConfig.Maxcount,
		}
		negCache = &MemoryCache{
			Backend:  make(map[string]Mesg),
			Expire:   time.Duration(cacheConfig.Expire) * time.Second / 2,
			Maxcount: cacheConfig.Maxcount,
		}
	case "memcache":
		cache = NewMemcachedCache(
			settings.Memcache.Servers,
			int32(cacheConfig.Expire))
		negCache = NewMemcachedCache(
			settings.Memcache.Servers,
			int32(cacheConfig.Expire/2))
	case "redis":
		cache = NewRedisCache(
			settings.Redis,
			int64(cacheConfig.Expire))
		negCache = NewRedisCache(
			settings.Redis,
			int64(cacheConfig.Expire/2))
	default:
		cache = &MemoryCache{
			Backend:  make(map[string]Mesg, cacheConfig.Maxcount),
			Expire:   time.Duration(cacheConfig.Expire) * time.Second,
			Maxcount: cacheConfig.Maxcount,
		}
		negCache = &MemoryCache{
			Backend:  make(map[string]Mesg),
			Expire:   time.Duration(cacheConfig.Expire) * time.Second / 2,
			Maxcount: cacheConfig.Maxcount,
		}
	}
	
	// Initialize hosts module
	hosts := NewHosts(settings.Hosts, settings.Redis)

	// Initialize blocklist module
	blocklistConfig := &blocklist.Config{
		Enable: settings.Blocklist.Enable,
		Backend: settings.Blocklist.Backend,
		File: settings.Blocklist.File,
		WhitelistFile: settings.Blocklist.WhitelistFile,
		RefreshInterval: settings.Blocklist.RefreshInterval,
		RedisEnable: settings.Blocklist.RedisEnable,
		RedisKey: settings.Blocklist.RedisKey,
		RedisWhitelistKey: settings.Blocklist.RedisWhitelistKey,
		RedisSettings: settings.Redis,
	}
	blocklist := blocklist.NewBlocklist(blocklistConfig)

	return &GODNSHandler{resolver: resolver, cache: cache, negCache: negCache, hosts: hosts, blocklist: blocklist}
}

// DoTCP handles DNS queries over TCP.
func (h *GODNSHandler) DoTCP(w dns.ResponseWriter, req *dns.Msg) {
	h.Do("tcp", w, req)
}

// DoUDP handles DNS queries over UDP.
func (h *GODNSHandler) DoUDP(w dns.ResponseWriter, req *dns.Msg) {
	h.Do("udp", w, req)
}

// Do performs the DNS query handling logic.
func (h *GODNSHandler) Do(Net string, w dns.ResponseWriter, req *dns.Msg) {
	// Only handle A, AAAA, MX and CNAME question
	if len(req.Question) == 0 || req.Question[0].Qtype != dns.TypeA && req.Question[0].Qtype != dns.TypeAAAA && req.Question[0].Qtype != dns.TypeMX && req.Question[0].Qtype != dns.TypeCNAME {
		dns.HandleFailed(w, req)
		return
	}
	
	q := req.Question[0]
	Q := Question{UnFqdn(q.Name), dns.Type(q.Qtype).String(), dns.Class(q.Qclass).String()}

	// --- Blocklist check ---
	domain := UnFqdn(q.Name)
	if h.blocklist.IsBlocked(domain) {
		log.Debug("Domain %s is blocked, returning NXDOMAIN", domain)
		m := new(dns.Msg)
		m.SetReply(req)
		m.SetRcode(req, dns.RcodeNameError) // NXDOMAIN
		w.WriteMsg(m)
		return
	}
	// --- End blocklist check ---


	if settings.Hosts.Enable {
		if ips, ok := h.hosts.Get(Q.qname, h.getQuestionType(q)); ok {
			mesg := new(dns.Msg)
			mesg.SetReply(req)
			
			if q.Qtype == dns.TypeMX {
				mesg.Authoritative = true
				rr := new(dns.MX)
				rr.Hdr = dns.RR_Header{Name: dns.Fqdn(Q.qname), Rrtype: dns.TypeMX, Class: dns.ClassINET, Ttl: settings.Hosts.TTL}
				rr.Preference = 10
				rr.Mx = "mail." + dns.Fqdn(Q.qname)
				mesg.Answer = []dns.RR{rr}
			} else {
				mesg.Authoritative = true
				var records []dns.RR
				for _, ip := range ips {
					if ip.To4() != nil {
						rr := new(dns.A)
						rr.Hdr = dns.RR_Header{Name: dns.Fqdn(Q.qname), Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: settings.Hosts.TTL}
						rr.A = ip
						records = append(records, rr)
					} else {
						rr := new(dns.AAAA)
						rr.Hdr = dns.RR_Header{Name: dns.Fqdn(Q.qname), Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: settings.Hosts.TTL}
						rr.AAAA = ip
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
	
	mesg, err = h.resolver.Lookup(Net, req)

	if err != nil {
		log.Warn("Resolve query error %s", err)
		dns.HandleFailed(w, req)

		// cache the failure, too!
		if err = h.negCache.Set(key, nil); err != nil {
			log.Warn("Set %s negative cache failed: %v", Q.String(), err)
		}
		return
	}
	
	w.WriteMsg(mesg)
	
	if len(mesg.Answer) > 0 {
		err = h.cache.Set(key, mesg)
		if err != nil {
			log.Warn("Set %s cache failed: %s", Q.String(), err.Error())
		}
		log.Debug("Insert %s into cache", Q.String())
	}
}

func (h *GODNSHandler) getQuestionType(q dns.Question) int {
	switch q.Qtype {
	case dns.TypeA:
		return _IP4Query
	case dns.TypeAAAA:
		return _IP6Query
	}
	return notIPQuery
}

