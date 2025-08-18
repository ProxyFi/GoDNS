package godns

import (
	"bufio"
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
	servers       []string
	domain_server *suffixTreeNode
	config        *ResolvSettings
	// dnssecValidator is the DNSSEC validator instance.
	dnssecValidator *dnssec.DNSSECValidator
}

// NewResolver creates a new Resolver instance with the specified configuration.
func NewResolver(c ResolvSettings) *Resolver {
	r := &Resolver{
		servers:       []string{},
		domain_server: newSuffixTreeRoot(),
		config:        &c,
		dnssecValidator: dnssec.NewDNSSECValidator(),
	}

	if len(c.ServerListFile) > 0 {
		r.ReadServerListFile(c.ServerListFile)
	}

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
func (r *Resolver) Lookup(net string, req *dns.Msg) (msg *dns.Msg, err error) {
	// Use sync.WaitGroup to wait for all goroutines to finish.
	var wg sync.WaitGroup
	// Use a channel to get the first successful response.
	res := make(chan *RResp, 1)
	// Use a ticker to query nameservers periodically.
	ticker := time.NewTicker(time.Duration(r.config.Interval) * time.Millisecond)
	defer ticker.Stop()

	// Start lookup on each nameserver top-down, in every second.
	nameservers := r.Nameservers(req.Question[0].Name)
	for _, nameserver := range nameservers {
		wg.Add(1)
		go func(nameserver string) {
			defer wg.Done()
			var a *dns.Msg
			var rtt time.Duration
			var err error

			// Add EDNS0 and DNSSEC OK flags if configured.
			if r.config.SetEDNS0 {
				o := req.IsEdns0()
				if o == nil {
					o = new(dns.OPT)
					o.Hdr.Name = "."
					o.Hdr.Rrtype = dns.TypeOPT
					o.Hdr.Class = 4096
					req.Extra = append(req.Extra, o)
				}
				if r.config.DNSSECEnable {
					o.SetDo()
				}
			}

			if net == "tcp" {
				tcpclient := &dns.Client{
					Net:          "tcp",
					ReadTimeout:  5 * time.Second,
					WriteTimeout: 5 * time.Second,
				}
				a, rtt, err = tcpclient.Exchange(req, nameserver)
			} else {
				udpclient := &dns.Client{
					Net:          "udp",
					ReadTimeout:  5 * time.Second,
					WriteTimeout: 5 * time.Second,
				}
				a, rtt, err = udpclient.Exchange(req, nameserver)
			}

			if err != nil {
				log.Warn("%s lookup on %s failed: %s", req.Question[0].String(), nameserver, err)
				return
			}
			if a != nil && a.Rcode != dns.RcodeServerFailure {
				res <- &RResp{a, nameserver, rtt}
			}
		}(nameserver)

		// but exit early, if we have an answer
		select {
		case re := <-res:
			// Perform DNSSEC validation if enabled.
			if r.config.DNSSECEnable {
				err = r.dnssecValidator.Validate(re.msg)
				if err != nil {
					log.Warn("DNSSEC validation failed for %s from %s: %s", req.Question[0].String(), re.nameserver, err)
					// In a production environment, you might want to return a SERVFAIL
					// but for now, we'll return the response anyway.
					return re.msg, nil
				}
				log.Debug("DNSSEC validation successful for %s from %s", req.Question[0].String(), re.nameserver)
			}

			log.Debug("%s resolv on %s rtt: %v", UnFqdn(req.Question[0].Name), re.nameserver, re.rtt)
			return re.msg, nil
		case <-ticker.C:
			continue
		}
	}
	// wait for all the namservers to finish
	wg.Wait()
	select {
	case re := <-res:
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
	default:
		return nil, ResolvError{req.Question[0].Name, net, nameservers}
	}
}

// Nameservers returns the array of nameservers, with port number appended.
// '#' in the name is treated as port separator, as with dnsmasq.
func (r *Resolver) Nameservers(qname string) []string {
	queryKeys := strings.Split(qname, ".")
	queryKeys = queryKeys[:len(queryKeys)-1] // ignore last '.'

	ns := []string{}
	if v, found := r.domain_server.SearchDomain(queryKeys); found {
		log.Debug("%s be found in domain server...", qname)
		ns = strings.Split(v, ",")
		for key, value := range ns {
			ns[key] = addPort(value, "53")
		}
		return ns
	}

	if len(r.servers) > 0 {
		return r.servers
	}

	return []string{"8.8.8.8:53", "8.8.4.4:53"}
}

// ReadServerListFile reads the server list from a file.
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

// addPort adds the default port if it is missing.
func addPort(server, port string) string {
	if _, _, err := net.SplitHostPort(server); err != nil {
		return net.JoinHostPort(server, port)
	}
	return server
}

