package godns

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
	"github.com/ProxyFi/GoDNS/features/dnssec"
	"github.com/ProxyFi/GoDNS/internal/log"
)

// ResolvError represents an error during DNS resolution.
type ResolvError struct {
	qname, net string
	nameservers []string
}

// Error implements the error interface for ResolvError.
func (e ResolvError) Error() string {
	errmsg := fmt.Sprintf("%s resolv failed on %s (%s)", e.qname, strings.Join(e.nameservers, "; "), e.net)
	return errmsg
}

// RResp represents a DNS response and its metadata.
type RResp struct {
	msg *dns.Msg
	nameserver string
	rtt time.Duration
}

// Resolver handles DNS queries to upstream servers.
type Resolver struct {
	// servers stores a list of default upstream nameservers.
	servers []string
	// domain_server is a suffix tree used for specific domain rules.
	domain_server *suffixTreeNode
	// config holds the resolver's settings.
	config *ResolvSettings
	// dnssecValidator is the DNSSEC validator instance.
	dnssecValidator *dnssec.DNSSECValidator
	// udpClient and tcpClient are reused for all DNS lookups to reduce overhead.
	udpClient *dns.Client
	tcpClient *dns.Client
	// latencyMap stores the last known RTT for each upstream server.
	latencyMap sync.Map // map[string]time.Duration
}

// NewResolver creates and initializes a new Resolver instance based on the provided settings.
func NewResolver(conf ResolvSettings) (*Resolver, error) {
	r := &Resolver{
		servers: conf.Servers,
		domain_server: newSuffixTreeRoot(),
		config: &conf,
		udpClient: &dns.Client{
			Net:     "udp",
			Timeout: time.Duration(conf.Timeout) * time.Second,
		},
		tcpClient: &dns.Client{
			Net:     "tcp",
			Timeout: time.Duration(conf.Timeout) * time.Second,
		},
	}

	// Initialize the latency map with a capacity of the number of servers.
	// We use sync.Map for concurrent read/write access without explicit locking.
	r.latencyMap = sync.Map{}
	for _, s := range r.servers {
		// Initialize all servers with a default RTT.
		r.latencyMap.Store(s, time.Duration(100)*time.Millisecond)
	}

	// Load specific domain configurations if a file is provided.
	if len(conf.ResolvFile) > 0 {
		r.ReadDomainServerFile(conf.ResolvFile)
	}
	
	// Load server list from file if specified.
	r.ReadServerListFile(conf.ServerListFile)

	// Enable DNSSEC validation if configured.
	if conf.DNSSECEnable {
		r.dnssecValidator = dnssec.NewDNSSECValidator(conf.TrustAnchorFile)
		if r.dnssecValidator == nil {
			log.Warn("DNSSEC validation disabled due to failure to load trust anchors.")
		} else {
			log.Info("DNSSEC validation enabled.")
		}
	}
	
	// Set EDNS0 if configured.
	if conf.SetEDNS0 {
		r.udpClient.SetEdns0(4096, true)
		r.tcpClient.SetEdns0(4096, true)
	}

	// Return the resolver and a nil error on success.
	return r, nil
}

// Lookup queries the DNS for the given request using multiple upstream servers.
// It tries to find the best nameserver based on latency if enabled.
func (r *Resolver) Lookup(net string, req *dns.Msg) (*dns.Msg, error) {
	var (
		errs []error
		rtt  time.Duration
		err  error
		res *dns.Msg
	)

	// Get a list of nameservers to query. This could be a static list or from a suffix tree.
	nameservers := r.getNameServers(req.Question[0].Name)
	if len(nameservers) == 0 {
		return nil, ResolvError{req.Question[0].Name, net, []string{}}
	}

	// If latency-based load balancing is enabled, sort the nameservers.
	if r.config.EnableLatencyBasedLoadBalancing {
		log.Debug("Latency-based load balancing is enabled. Sorting servers.")
		nameservers = r.sortNameserversByLatency(nameservers)
	}

	// Iterate through the selected nameservers and try to get a response.
	for _, server := range nameservers {
		resp := new(RResp)
		resp.nameserver = server

		// Use the appropriate client (UDP or TCP) for the query.
		if net == "tcp" {
			res, rtt, err = r.tcpClient.Exchange(req, server)
		} else {
			res, rtt, err = r.udpClient.Exchange(req, server)
		}
		
		// If the query was successful, update the latency and return the response.
		if err == nil {
			log.Debug("Resolve successfully by %s", server)
			resp.msg = res
			resp.rtt = rtt
			
			// Store the RTT for latency-based load balancing.
			r.latencyMap.Store(server, rtt)

			// Perform DNSSEC validation if enabled.
			if r.config.DNSSECEnable && r.dnssecValidator != nil {
				if r.dnssecValidator.Validate(resp.msg) {
					log.Debug("DNSSEC validation successful for %s", req.Question[0].Name)
				} else {
					log.Warn("DNSSEC validation failed for %s", req.Question[0].Name)
					return resp.msg, fmt.Errorf("DNSSEC validation failed")
				}
			}
			
			return resp.msg, nil
		}

		// If the query failed, log the error and store it for later.
		log.Warn("Resolve %s failed with error: %s", server, err)
		errs = append(errs, err)

		// Set a high penalty for this server to de-prioritize it in future lookups.
		r.latencyMap.Store(server, time.Duration(10)*time.Second)
	}

	// If all queries failed, return a combined error.
	return nil, ResolvError{req.Question[0].Name, net, nameservers}
}

// sortNameserversByLatency sorts a slice of nameservers based on their recorded latency.
// It prioritizes servers with a known, low RTT.
func (r *Resolver) sortNameserversByLatency(servers []string) []string {
	// Create a temporary struct to hold both the server address and its RTT.
	type serverLatency struct {
		address string
		rtt     time.Duration
	}

	// Populate the slice with server information.
	var latencies []serverLatency
	for _, s := range servers {
		rtt, ok := r.latencyMap.Load(s)
		if !ok {
			// If no RTT data exists, use a large default value.
			// This ensures that servers with no recent data are tried after those with known RTTs.
			latencies = append(latencies, serverLatency{address: s, rtt: time.Duration(100)*time.Second})
		} else {
			latencies = append(latencies, serverLatency{address: s, rtt: rtt.(time.Duration)})
		}
	}

	// Sort the slice by RTT in ascending order.
	sort.Slice(latencies, func(i, j int) bool {
		return latencies[i].rtt < latencies[j].rtt
	})

	// Create a new sorted list of server addresses.
	sortedServers := make([]string, len(latencies))
	for i, sl := range latencies {
		sortedServers[i] = sl.address
	}

	return sortedServers
}

// getNameServers returns a list of nameservers to be used for a given query.
// It first checks for a domain-specific rule, then falls back to the default list.
func (r *Resolver) getNameServers(qname string) []string {
	queryKeys := dns.SplitDomainName(qname)
	// Check for a specific domain-server configuration.
	if v, found := r.domain_server.SearchDomain(queryKeys); found {
		log.Debug("%s found in domain server, using specific nameservers.", qname)
		ns := strings.Split(v, ",")
		for key, value := range ns {
			ns[key] = addPort(value, "53")
		}
		return ns
	}

	// If no specific rule is found, use the default server list.
	if len(r.servers) > 0 {
		return r.servers
	}

	// Fallback to hardcoded public DNS servers if no other servers are configured.
	return []string{"8.8.8.8:53", "8.8.4.4:53"}
}

// ReadDomainServerFile reads and parses a domain-specific nameserver configuration file.
func (r *Resolver) ReadDomainServerFile(filePath string) {
	if len(filePath) == 0 {
		return
	}
	f, err := os.Open(filePath)
	if err != nil {
		log.Error("open domain server file failed: %s", err)
		return
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "#") || line == "" {
			continue
		}

		parts := strings.Fields(line)
		if len(parts) < 2 {
			continue
		}

		domain := strings.ToLower(parts[0])
		if !isDomain(domain) {
			continue
		}

		domainKeys := dns.SplitDomainName(domain)
		server := parts[1]
		if len(domainKeys) > 0 {
			r.domain_server.InsertDomain(domainKeys, server)
		}
	}
}

// ReadServerListFile reads a list of nameservers from a file.
// The file should contain one server per line, in "ip" or "ip:port" format.
func (r *Resolver) ReadServerListFile(filePath string) {
	if len(filePath) == 0 {
		return
	}

	f, err := os.Open(filePath)
	if err != nil {
		log.Error("open server list file %s failed: %s", filePath, err)
		return
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "#") || line == "" {
			continue
		}

		pair := strings.Split(line, ":")
		if len(pair) == 2 {
			if _, err := dns.ParseRR(line); err == nil {
				r.servers = append(r.servers, line)
			}
		} else if len(pair) == 1 {
			if net.ParseIP(pair[0]) != nil {
				r.servers = append(r.servers, addPort(pair[0], "53"))
			}
		}
	}
}

// addPort adds the default port to a server address if it is not already present.
func addPort(server, port string) string {
	if !strings.Contains(server, ":") {
		return server + ":" + port
	}
	return server
}
