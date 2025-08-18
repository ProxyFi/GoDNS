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

// Resolver handles DNS queries to upstream servers.
type Resolver struct {
	// servers stores a list of default upstream nameservers.
	servers       []string
	// domain_server is a suffix tree used for specific domain rules.
	domain_server *suffixTreeNode
	// config holds the resolver's settings.
	config        *ResolvSettings
	// dnssecValidator is the DNSSEC validator instance.
	dnssecValidator *dnssec.DNSSECValidator
	// udpClient and tcpClient are reused for all DNS lookups to reduce overhead.
	udpClient *dns.Client
	tcpClient *dns.Client
}

// NewResolver creates and initializes a new Resolver instance.
// It sets up DNS clients and loads server lists from configured files.
func NewResolver(c ResolvSettings) *Resolver {
	r := &Resolver{
		servers:       []string{},
		domain_server: newSuffixTreeRoot(),
		config:        &c,
		dnssecValidator: dnssec.NewDNSSECValidator(),
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

	return r
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

		log.Debug("%s resolv on %s rtt: %v", UnFqdn(req.Question[0].Name), re.nameserver, re.rtt)
		return re.msg, nil

	case <-time.After(time.Duration(r.config.Timeout) * time.Second):
		// The lookup timed out.
		return nil, ResolvError{req.Question[0].Name, net, nameservers}
	}
}

// Nameservers returns the list of nameservers to use for a given query name.
// It prioritizes specific rules from the suffix tree over the default list.
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

	// If no specific rule is found, use the default server list.
	if len(r.servers) > 0 {
		return r.servers
	}

	// Fallback to hardcoded public DNS servers if no other servers are configured.
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
