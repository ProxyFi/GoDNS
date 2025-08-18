// File: resolver.go

package godns

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"time"
	"sort"

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
	msg        *dns.Msg
	nameserver string
	rtt        time.Duration
}

// nameserverState holds a nameserver address and its measured Round-Trip Time (RTT).
type nameserverState struct {
	addr string
	rtt  time.Duration
}

// Resolver handles DNS queries to upstream servers.
type Resolver struct {
	// servers stores a list of default upstream nameservers.
	// This field is used only during initial configuration and is deprecated in favor of rttServers.
	servers []string
	// domain_server is a suffix tree used for specific domain rules.
	domain_server *suffixTreeNode
	// config holds the resolver's settings.
	config        *ResolvSettings
	// dnssecValidator is the DNSSEC validator instance.
	dnssecValidator *dnssec.DNSSECValidator
	// udpClient and tcpClient are reused for all DNS lookups to reduce overhead.
	udpClient *dns.Client
	tcpClient *dns.Client
	// rttServers stores a map of nameservers and their measured RTTs for load balancing.
	rttServers    map[string]*nameserverState
	serversMutex  sync.RWMutex
}

// NewResolver creates and initializes a new Resolver instance.
// It sets up DNS clients and loads server lists from configured files.
// This function now returns an error if DNSSEC trust anchors cannot be loaded.
func NewResolver(c ResolvSettings) (*Resolver, error) {
	// Initialize the DNSSEC validator.
	// This call now includes the trust anchor file path from ResolvSettings.
	dnssecValidator, err := dnssec.NewDNSSECValidator(c.TrustAnchorFile)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize DNSSEC validator: %w", err)
	}

	r := &Resolver{
		servers:       []string{},
		domain_server: newSuffixTreeRoot(),
		config:        &c,
		dnssecValidator: dnssecValidator,
		// Initialize reusable DNS clients with timeouts.
		udpClient: &dns.Client{
			Net:          "udp",
			ReadTimeout:  5 * time.Second,
			WriteTimeout: 5 * time.Second,
		},
		tcpClient: &dns.Client{
			Net:          "tcp",
			ReadTimeout:  5 * time.Second,
			WriteTimeout: 5 * time.Second,
		},
		rttServers: make(map[string]*nameserverState),
		serversMutex: sync.RWMutex{},
	}

	// Load server list from a dedicated file, if configured.
	if len(c.ServerListFile) > 0 {
		r.ReadServerListFile(c.ServerListFile)
	}

	// Load upstream servers from a standard resolv.conf file.
	if len(c.ResolvFile) > 0 {
		clientConfig, err := dns.ClientConfigFromFile(c.ResolvFile)
		if err != nil {
			log.Error(":%s is not a valid resolv.conf file\n", c.ResolvFile)
			log.Error("%s", err)
			panic(err)
		}

		for _, server := range clientConfig.Servers {
			r.servers = append(r.servers, net.JoinHostPort(server, clientConfig.Port))
		}
	}
	
	// Populate rttServers map from the loaded server list.
	// This map will be used for latency-based load balancing.
	if len(r.servers) > 0 {
		for _, server := range r.servers {
			r.rttServers[server] = &nameserverState{
				addr: server, 
				rtt: time.Duration(c.Timeout) * time.Second,
			}
		}
	} else {
		// Fallback to hardcoded public DNS servers if none are configured.
		defaultServers := []string{"8.8.8.8:53", "8.8.4.4:53"}
		for _, server := range defaultServers {
			r.rttServers[server] = &nameserverState{
				addr: server,
				rtt: time.Duration(c.Timeout) * time.Second,
			}
		}
	}

	return r, nil
}

// Lookup performs a DNS query to the upstream nameservers.
// It concurrently queries multiple servers and returns the first successful response.
// This function uses a context to manage goroutines and prevent leaks.
func (r *Resolver) Lookup(net string, req *dns.Msg) (msg *dns.Msg, err error) {
	// Use a context to cancel all concurrent requests once one succeeds.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel() // Ensure cancellation is called on function exit.

	var wg sync.WaitGroup
	// Create a buffered channel to receive the first successful response.
	resChan := make(chan *RResp, 1)

	// Get the list of nameservers to query.
	nameservers := r.Nameservers(req.Question[0].Name)

	for _, nameserver := range nameservers {
		wg.Add(1)
		go func(nameserver string) {
			defer wg.Done()
			
			// Check if the context has been canceled. If so, exit early.
			select {
			case <-ctx.Done():
				return
			default:
			}

			// Copy the request to prevent data races during concurrent modification.
			reqCopy := req.Copy()

			// Add EDNS0 and DNSSEC OK flags if configured.
			if r.config.SetEDNS0 {
				o := reqCopy.IsEdns0()
				if o == nil {
					o = new(dns.OPT)
					o.Hdr.Name = "."
					o.Hdr.Rrtype = dns.TypeOPT
					o.Hdr.Class = 4096
					reqCopy.Extra = append(reqCopy.Extra, o)
				}
				if r.config.DNSSECEnable {
					o.SetDo()
				}
			}

			var a *dns.Msg
			var rtt time.Duration
			var lookupErr error

			// Use the appropriate reusable client based on the network type.
			if net == "tcp" {
				a, rtt, lookupErr = r.tcpClient.Exchange(reqCopy, nameserver)
			} else {
				a, rtt, lookupErr = r.udpClient.Exchange(reqCopy, nameserver)
			}

			if lookupErr != nil {
				log.Warn("%s lookup on %s failed: %s", req.Question[0].String(), nameserver, lookupErr)
				// Penalize the server by setting its RTT to a high value.
				r.serversMutex.Lock()
				if state, ok := r.rttServers[nameserver]; ok {
					state.rtt = time.Duration(r.config.Timeout) * time.Second
				}
				r.serversMutex.Unlock()
				return
			}
			if a != nil && a.Rcode != dns.RcodeServerFailure {
				// Send the successful response to the channel.
				resChan <- &RResp{a, nameserver, rtt}
			}
		}(nameserver)
	}

	// Use a separate goroutine to wait for all lookups to finish.
	// This ensures `resChan` is closed and the main select block can handle it.
	go func() {
		wg.Wait()
		close(resChan)
	}()

	// Use a select statement to wait for either the first response or a timeout.
	select {
	case re, ok := <-resChan:
		// Check if the channel was closed without a successful response.
		if !ok {
			return nil, ResolvError{req.Question[0].Name, net, nameservers}
		}

		// Perform DNSSEC validation if enabled.
		if r.config.DNSSECEnable {
			err = r.dnssecValidator.Validate(re.msg)
			if err != nil {
				log.Warn("DNSSEC validation failed for %s from %s: %s", req.Question[0].String(), re.nameserver, err)
				return re.msg, nil
			}
			log.Debug("DNSSEC validation successful for %s from %s", req.Question[0].String(), re.nameserver)
		}
		
		// Update the RTT for the successful nameserver based on load balancing setting.
		if r.config.LoadBalanceEnable {
			r.serversMutex.Lock()
			if state, ok := r.rttServers[re.nameserver]; ok {
				// Use an Exponential Moving Average (EMA) for smoothing.
				// This gives more weight to recent measurements.
				state.rtt = time.Duration(float64(state.rtt)*0.9 + float64(re.rtt)*0.1)
			}
			r.serversMutex.Unlock()
		}

		log.Debug("%s resolv on %s rtt: %v", UnFqdn(req.Question[0].Name), re.nameserver, re.rtt)
		return re.msg, nil

	case <-time.After(time.Duration(r.config.Timeout) * time.Second):
		// The lookup timed out.
		return nil, ResolvError{req.Question[0].Name, net, nameservers}
	}
}

// Nameservers returns the list of nameservers to use for a given query name.
// It prioritizes specific rules from the suffix tree over the default list.
// If load balancing is enabled, it sorts the default servers by RTT.
func (r *Resolver) Nameservers(qname string) []string {
	// Split the domain name into parts and ignore the trailing dot.
	queryKeys := strings.Split(strings.Trim(qname, "."), ".")
	
	// Use the suffix tree to find specific nameservers for a domain.
	if v, found := r.domain_server.SearchDomain(queryKeys); found {
		log.Debug("%s found in domain server, using specific nameservers.", qname)
		ns := strings.Split(v, ",")
		for key, value := range ns {
			ns[key] = addPort(value, "53")
		}
		return ns
	}

	// If no specific rule is found and load balancing is enabled, sort by RTT.
	if r.config.LoadBalanceEnable {
		r.serversMutex.RLock()
		defer r.serversMutex.RUnlock()
		
		var states []*nameserverState
		for _, state := range r.rttServers {
			states = append(states, state)
		}

		// Sort the nameservers by their measured RTT.
		sort.Slice(states, func(i, j int) bool {
			return states[i].rtt < states[j].rtt
		})

		var sortedServers []string
		for _, state := range states {
			sortedServers = append(sortedServers, state.addr)
		}

		if len(sortedServers) > 0 {
			return sortedServers
		}
	}

	// Fallback to the original, unsorted list if no RTT data or load balancing is disabled.
	if len(r.servers) > 0 {
		return r.servers
	}

	// Final fallback to hardcoded public DNS servers if no other servers are configured.
	return []string{"8.8.8.8:53", "8.8.4.4:53"}
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
			r.servers = append(r.servers, net.JoinHostPort(pair[0], pair[1]))
		} else {
			r.servers = append(r.servers, net.JoinHostPort(line, "53"))
		}
	}
}

// addPort appends the default port if a server address is missing it.
func addPort(server, port string) string {
	if _, _, err := net.SplitHostPort(server); err != nil {
		return net.JoinHostPort(server, port)
	}
	return server
}
